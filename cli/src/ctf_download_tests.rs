use super::*;
use std::net::TcpListener;
use std::thread::JoinHandle;

const IMAGE: &[u8] = b"\xe9CTF firmware\0\xff";
type Response = (u16, Vec<u8>, String);

fn serve(make: impl FnOnce(&str) -> Vec<Response>) -> (String, JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let responses = make(&base);
    let worker = std::thread::spawn(move || {
        let mut requests = Vec::new();
        for (status, body, headers) in responses {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 4096];
            let header_end = loop {
                let n = socket.read(&mut buf).unwrap();
                assert!(n > 0);
                request.extend_from_slice(&buf[..n]);
                if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                    break end + 4;
                }
            };
            let length = String::from_utf8_lossy(&request[..header_end])
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            while request.len() < header_end + length {
                let n = socket.read(&mut buf).unwrap();
                assert!(n > 0);
                request.extend_from_slice(&buf[..n]);
            }
            requests.push(String::from_utf8(request).unwrap());
            write!(socket, "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n", body.len()).unwrap();
            socket.write_all(&body).unwrap();
        }
        requests
    });
    (base, worker)
}

fn metadata(url: String) -> Firmware {
    Firmware {
        version: 2,
        url,
        sha256: hex::encode_lower(&Sha256::digest(IMAGE)),
        size_bytes: IMAGE.len() as u64,
    }
}

const SIGNED_ENDPOINT: &str = "https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com/firmware-bucket/ctf/gate/2.bin";
const SIGNED_URL: &str = "https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com/firmware-bucket/ctf/gate/2.bin?X-Amz-Signature=must-not-escape";
const SIGNATURE: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
const ACCESS_KEY: &str = "TESTACCESSKEYNOTTOBELOGGED";

fn future_expiry() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        + 300
}

fn aws_date(timestamp: i64) -> String {
    let mut days = timestamp / 86400;
    let mut year = 1970;
    loop {
        let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
        let length = if leap { 366 } else { 365 };
        if days < length {
            break;
        }
        days -= length;
        year += 1;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let months = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 0;
    while days >= months[month] {
        days -= months[month];
        month += 1;
    }
    let second = timestamp % 86400;
    format!(
        "{year:04}{:02}{:02}T{:02}{:02}{:02}Z",
        month + 1,
        days + 1,
        second / 3600,
        second / 60 % 60,
        second % 60
    )
}

fn signed_url_at(timestamp: i64, lifetime: i64) -> String {
    let date = aws_date(timestamp);
    let mut url = Url::parse(SIGNED_ENDPOINT).unwrap();
    url.query_pairs_mut()
        .append_pair("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
        .append_pair(
            "X-Amz-Credential",
            &format!("{ACCESS_KEY}/{}/auto/s3/aws4_request", &date[..8]),
        )
        .append_pair("X-Amz-Date", &date)
        .append_pair("X-Amz-Expires", &lifetime.to_string())
        .append_pair("X-Amz-SignedHeaders", "host")
        .append_pair("X-Amz-Signature", SIGNATURE);
    url.into()
}

fn grant_value(firmware: Firmware, expires_at: Option<i64>) -> serde_json::Value {
    serde_json::json!({
        "challenge": "gate",
        "firmware": firmware,
        "expires_at": expires_at,
    })
}

fn grant(firmware: Firmware, expires_at: Option<i64>) -> Vec<u8> {
    serde_json::to_vec(&grant_value(firmware, expires_at)).unwrap()
}

fn catalog(firmware: Option<Firmware>) -> Vec<u8> {
    serde_json::to_vec(&vec![Challenge {
        slug: "gate".into(),
        title: "Write then notify".into(),
        difficulty: "medium".into(),
        firmware,
    }])
    .unwrap()
}

fn opts(url: String) -> ApiOpts {
    ApiOpts {
        url: Some(url),
        token: Some("player-secret".into()),
        user: Some("alice".into()),
    }
}

#[test]
fn valid_download_is_private_and_removed_on_drop() {
    let (base, worker) = serve(|_| {
        vec![(
            200,
            IMAGE.to_vec(),
            "Content-Type: application/octet-stream\r\n".into(),
        )]
    });
    let image = download_firmware(&metadata(format!("{base}/2.bin"))).unwrap();
    assert_eq!(std::fs::read(&image.bin).unwrap(), IMAGE);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&image.dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
    let dir = image.dir.clone();
    drop(image);
    assert!(!dir.exists());
    let request = worker.join().unwrap().pop().unwrap().to_ascii_lowercase();
    assert!(request.starts_with("get /2.bin "));
    assert!(request.contains(&format!("user-agent: {}", UA.to_ascii_lowercase())));
    assert!(!request.contains("authorization:"));
    assert!(!request.contains("x-user:"));
    assert!(!request.contains("x-ctf-token:"));
}

#[test]
fn metadata_rejects_invalid_versions_sizes_digests_and_urls() {
    let valid = metadata("https://cdn.infishark.com/ctf/gate/2.bin".into());
    validate_firmware(&valid).unwrap();
    assert!(
        validate_firmware(&Firmware {
            version: 0,
            ..valid.clone()
        })
        .is_err()
    );
    for size_bytes in [0, MAX_FIRMWARE_SIZE + 1, u64::MAX] {
        assert!(
            validate_firmware(&Firmware {
                size_bytes,
                ..valid.clone()
            })
            .is_err()
        );
    }
    for sha256 in ["", "abc", &"g".repeat(64), &"A".repeat(64)] {
        assert!(
            validate_firmware(&Firmware {
                sha256: sha256.into(),
                ..valid.clone()
            })
            .is_err()
        );
    }
    for raw in [
        "http://cdn.infishark.com/2.bin",
        "file:///tmp/image.bin",
        "ftp://cdn.infishark.com/2.bin",
        "https://user:secret@cdn.infishark.com/2.bin",
        "https://cdn.infishark.com/2.bin#fragment",
        "not-a-url",
        "http://127.0.0.1.evil.example/2.bin",
        "http://localhost.evil.example/2.bin",
    ] {
        assert!(firmware_url(raw).is_err(), "{raw}");
    }
    firmware_url("http://127.0.0.1:1234/2.bin").unwrap();
    firmware_url("http://[::1]:1234/2.bin").unwrap();
}

#[test]
fn preparation_verifies_firmware_with_authorized_grant_before_issue() {
    let (base, worker) = serve(|base| {
        vec![
            (
                200,
                grant(metadata(format!("{base}/firmware/2.bin")), None),
                String::new(),
            ),
            (200, IMAGE.to_vec(), String::new()),
        ]
    });
    let spec = resolve_start("gate", None, false).unwrap();
    let prepared = prepare_start(&spec, false, &opts(base)).unwrap();
    assert_eq!(std::fs::read(&prepared.bin).unwrap(), IMAGE);
    assert_eq!(prepared.firmware.as_ref().unwrap().version, 2);
    assert!(prepared.api.is_some());
    let path = prepared.bin.clone();
    drop(prepared);
    assert!(!path.exists());
    let requests = worker.join().unwrap();
    assert_eq!(requests.len(), 2);
    let (headers, body) = requests[0].split_once("\r\n\r\n").unwrap();
    let headers = headers.to_ascii_lowercase();
    assert!(headers.starts_with("post /v1/challenges/gate/firmware "));
    assert!(headers.contains("authorization: bearer player-secret"));
    assert!(headers.contains("content-type: application/json"));
    assert_eq!(body, "{}");
    assert!(requests[1].starts_with("GET /firmware/2.bin "));
    let artifact = requests[1].to_ascii_lowercase();
    for secret in ["player-secret", "authorization:", "x-user:", "x-ctf-token:"] {
        assert!(!artifact.contains(secret));
    }
    assert!(requests.iter().all(|r| !r.contains("/issue ")));
}

#[test]
fn corrupt_short_and_oversized_downloads_stop_before_issue() {
    for (body, error) in [
        (vec![0; IMAGE.len()], "SHA-256 mismatch"),
        (IMAGE[..IMAGE.len() - 1].to_vec(), "size mismatch"),
        ([IMAGE, b"extra"].concat(), "size mismatch"),
    ] {
        let (base, worker) = serve(|base| {
            vec![
                (
                    200,
                    grant(metadata(format!("{base}/2.bin")), None),
                    String::new(),
                ),
                (200, body, String::new()),
            ]
        });
        let spec = resolve_start("gate", None, false).unwrap();
        let err = prepare_start(&spec, false, &opts(base))
            .unwrap_err()
            .to_string();
        assert!(err.contains(error), "{err}");
        let requests = worker.join().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].starts_with("POST /v1/challenges/gate/firmware "));
        assert!(requests.iter().all(|r| !r.contains("/issue ")));
    }
}

#[test]
fn unknown_unpublished_and_legacy_catalogs_remain_public_without_guessing_urls() {
    for (body, has_challenge) in [
        (b"[]".to_vec(), false),
        (catalog(None), true),
        (
            br#"[{"slug":"gate","title":"Write then notify","difficulty":"medium"}]"#.to_vec(),
            true,
        ),
    ] {
        let (base, worker) = serve(|_| vec![(200, body, String::new())]);
        let list = Api::at(&base, "player-secret", "alice")
            .challenges()
            .unwrap();
        assert_eq!(!list.is_empty(), has_challenge);
        assert!(list.iter().all(|c| c.firmware.is_none()));
        let requests = worker.join().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].starts_with("GET /v1/challenges "));
        assert!(!requests[0].to_ascii_lowercase().contains("authorization:"));
    }
}

#[test]
fn legacy_catalog_responses_are_not_accepted_as_grants() {
    for body in [
        b"[]".to_vec(),
        catalog(None),
        catalog(Some(metadata(SIGNED_URL.into()))),
    ] {
        let (base, worker) = serve(|_| vec![(200, body, String::new())]);
        let spec = resolve_start("gate", None, false).unwrap();
        let err = prepare_start(&spec, false, &opts(base)).unwrap_err();
        assert_eq!(err.to_string(), "invalid CTF firmware grant response");
        let requests = worker.join().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].starts_with("POST /v1/challenges/gate/firmware "));
    }
}

#[test]
fn invalid_metadata_stops_before_download_or_issue() {
    let (base, worker) = serve(|base| {
        let mut firmware = metadata(format!("{base}/2.bin"));
        firmware.size_bytes = MAX_FIRMWARE_SIZE + 1;
        vec![(200, grant(firmware, None), String::new())]
    });
    let spec = resolve_start("gate", None, false).unwrap();
    let err = prepare_start(&spec, false, &opts(base))
        .unwrap_err()
        .to_string();
    assert!(err.contains("app partition limit"), "{err}");
    assert_eq!(worker.join().unwrap().len(), 1);
}

fn assert_safe_error(error: anyhow::Error) {
    for rendered in [format!("{error:#}"), format!("{error:?}")] {
        for secret in [
            "must-not-escape",
            "X-Amz-",
            "provider-body",
            SIGNED_ENDPOINT,
            SIGNATURE,
            ACCESS_KEY,
        ] {
            assert!(!rendered.contains(secret), "{rendered}");
        }
    }
}

#[test]
fn grant_route_uses_account_or_explicit_bearer_and_empty_json() {
    for token in ["ctf_account-secret", "player-secret"] {
        let expiry = future_expiry();
        let signed_url = signed_url_at(expiry - 300, 300);
        let (base, worker) = serve(|_| {
            vec![(
                200,
                grant(metadata(signed_url.clone()), Some(expiry)),
                String::new(),
            )]
        });
        let granted = Api::at(&base, token, "alice")
            .firmware_grant("gate")
            .unwrap();
        assert_eq!(granted.firmware.url, signed_url);
        granted.validate("gate").unwrap();
        for debug in [format!("{granted:?}"), format!("{:?}", granted.firmware)] {
            assert!(!debug.contains(SIGNED_ENDPOINT));
            assert!(!debug.contains(SIGNATURE));
            assert!(!debug.contains(ACCESS_KEY));
        }
        let report = granted.into_report();
        assert_eq!(report.version, 2);
        assert_eq!(report.url, "[redacted]");
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("X-Amz-"));
        assert!(!json.contains(SIGNED_ENDPOINT));
        let requests = worker.join().unwrap();
        assert_eq!(requests.len(), 1);
        let (headers, body) = requests[0].split_once("\r\n\r\n").unwrap();
        let headers = headers.to_ascii_lowercase();
        assert!(headers.starts_with("post /v1/challenges/gate/firmware "));
        assert!(headers.contains(&format!("authorization: bearer {token}")));
        assert!(headers.contains("content-type: application/json"));
        assert_eq!(headers.contains("x-user:"), !token.starts_with("ctf_"));
        assert_eq!(body, "{}");
    }
    let api = Api {
        url: "http://127.0.0.1:1".into(),
        token: None,
        user: "alice".into(),
    };
    assert!(
        api.firmware_grant("gate")
            .unwrap_err()
            .to_string()
            .contains("INFISHARK_CTF_TOKEN")
    );
    let api = Api::at("http://127.0.0.1:1", "ctf_secret", "alice");
    assert!(
        api.firmware_grant("../gate")
            .unwrap_err()
            .to_string()
            .contains("invalid challenge slug")
    );
}

#[test]
fn grant_http_errors_are_static_without_catalog_fallback_or_redirects() {
    for (status, expected) in [
        (401, "valid credentials"),
        (403, "active membership"),
        (404, "grant not found"),
        (503, "billing or firmware artifact unavailable"),
        (302, "HTTP 302"),
        (307, "HTTP 307"),
        (429, "HTTP 429"),
        (500, "HTTP 500"),
    ] {
        let (base, worker) = serve(|base| {
            vec![(
                status,
                format!("provider-body {SIGNED_URL}").into_bytes(),
                format!("Location: {base}/leak?X-Amz-Signature=must-not-escape\r\n"),
            )]
        });
        let spec = resolve_start("gate", None, false).unwrap();
        let error = prepare_start(&spec, false, &opts(base)).unwrap_err();
        assert!(error.to_string().contains(expected), "{error:#}");
        assert_safe_error(error);
        let requests = worker.join().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].starts_with("POST /v1/challenges/gate/firmware "));
    }
}

#[test]
fn grant_shape_requires_exact_objects_fields_and_integer_types() {
    let expiry = future_expiry();
    let valid = grant_value(metadata(signed_url_at(expiry - 300, 300)), Some(expiry));
    let mut bodies = vec![
        b"null".to_vec(),
        b"[]".to_vec(),
        b"\"must-not-escape\"".to_vec(),
        b"{invalid provider-body".to_vec(),
        serde_json::to_vec(&serde_json::json!([
            "gate",
            valid["firmware"],
            valid["expires_at"]
        ]))
        .unwrap(),
        format!("{} null", valid).into_bytes(),
        valid
            .to_string()
            .replacen("{", "{\"challenge\":\"gate\",", 1)
            .into_bytes(),
    ];
    for field in ["challenge", "firmware", "expires_at"] {
        let mut value = valid.clone();
        value.as_object_mut().unwrap().remove(field);
        bodies.push(serde_json::to_vec(&value).unwrap());
    }
    for (field, value) in [
        ("challenge", serde_json::json!(null)),
        ("firmware", serde_json::json!(null)),
        (
            "firmware",
            serde_json::json!([2, SIGNED_URL, valid["firmware"]["sha256"], IMAGE.len()]),
        ),
        ("expires_at", serde_json::json!("must-not-escape")),
        ("expires_at", serde_json::json!(u64::MAX)),
        ("expires_at", serde_json::json!(1.5)),
        ("expires_at", serde_json::json!(true)),
        ("extra", serde_json::json!(SIGNED_URL)),
    ] {
        let mut invalid = valid.clone();
        invalid[field] = value;
        bodies.push(serde_json::to_vec(&invalid).unwrap());
    }
    for field in ["version", "url", "sha256", "size_bytes"] {
        let mut value = valid.clone();
        value["firmware"].as_object_mut().unwrap().remove(field);
        bodies.push(serde_json::to_vec(&value).unwrap());
        let nested = valid["firmware"].to_string();
        bodies.push(
            valid
                .to_string()
                .replace(
                    &nested,
                    &nested.replacen(
                        "{",
                        &format!("{{\"{field}\":{},", valid["firmware"][field]),
                        1,
                    ),
                )
                .into_bytes(),
        );
    }
    for (field, value) in [
        ("version", serde_json::json!(u64::from(u32::MAX) + 1)),
        ("version", serde_json::json!(-1)),
        ("version", serde_json::json!(2.0)),
        ("url", serde_json::json!(42)),
        ("sha256", serde_json::json!(null)),
        ("size_bytes", serde_json::json!(-1)),
        ("size_bytes", serde_json::json!(1.5)),
        ("extra", serde_json::json!(SIGNED_URL)),
    ] {
        let mut invalid = valid.clone();
        invalid["firmware"][field] = value;
        bodies.push(serde_json::to_vec(&invalid).unwrap());
    }
    for body in bodies {
        let (base, worker) = serve(|_| vec![(200, body, String::new())]);
        let error = Api::at(&base, "ctf_secret", "alice")
            .firmware_grant("gate")
            .unwrap_err();
        assert_eq!(error.to_string(), "invalid CTF firmware grant response");
        assert_safe_error(error);
        assert_eq!(worker.join().unwrap().len(), 1);
    }
}

#[test]
fn grants_reject_expiry_mismatch_and_invalid_metadata_before_download() {
    let expiry = future_expiry();
    let valid = grant_value(metadata(signed_url_at(expiry - 300, 300)), Some(expiry));
    let now = expiry - 300;
    for (field, value) in [
        ("challenge", serde_json::json!("must-not-escape")),
        ("expires_at", serde_json::json!(-1)),
        ("expires_at", serde_json::json!(i64::MIN)),
        ("expires_at", serde_json::json!(i64::MAX)),
        ("expires_at", serde_json::json!(now + 601)),
        ("expires_at", serde_json::json!(0)),
        ("expires_at", serde_json::json!(now - 1)),
        ("expires_at", serde_json::json!(now)),
        ("expires_at", serde_json::json!(null)),
        ("version", serde_json::json!(0)),
        ("size_bytes", serde_json::json!(0)),
        ("size_bytes", serde_json::json!(MAX_FIRMWARE_SIZE + 1)),
        ("size_bytes", serde_json::json!(u64::MAX)),
        ("sha256", serde_json::json!("A".repeat(64))),
        ("sha256", serde_json::json!("must-not-escape")),
        (
            "url",
            serde_json::json!(format!(
                "https://cdn.infishark.com/{}",
                "a".repeat(MAX_FIRMWARE_URL_BYTES)
            )),
        ),
    ] {
        let mut invalid = valid.clone();
        if ["challenge", "expires_at"].contains(&field) {
            invalid[field] = value;
        } else {
            invalid["firmware"][field] = value;
        }
        let (base, worker) =
            serve(|_| vec![(200, serde_json::to_vec(&invalid).unwrap(), String::new())]);
        let spec = resolve_start("gate", None, false).unwrap();
        assert_safe_error(prepare_start(&spec, false, &opts(base)).unwrap_err());
        let requests = worker.join().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].starts_with("POST /v1/challenges/gate/firmware "));
    }
    let (base, worker) = serve(|_| {
        vec![(
            200,
            vec![b' '; (MAX_FIRMWARE_GRANT_BYTES + 1) as usize],
            String::new(),
        )]
    });
    assert_eq!(
        Api::at(&base, "ctf_secret", "alice")
            .firmware_grant("gate")
            .unwrap_err()
            .to_string(),
        "CTF firmware grant response is too large"
    );
    worker.join().unwrap();
}

#[test]
fn signed_grants_require_the_exact_canonical_s3_r2_account_host() {
    let expiry = future_expiry();
    let signed_url = signed_url_at(expiry - 300, 300);
    for url in [
        signed_url.replace("https://", "http://"),
        signed_url.replace(
            "0123456789abcdef0123456789abcdef.",
            "0123456789abcdef0123456789abcde.",
        ),
        signed_url.replace(
            "0123456789abcdef0123456789abcdef.",
            "g123456789abcdef0123456789abcdef.",
        ),
        signed_url.replace("0123456789abcdef", "0123456789ABCDEF"),
        signed_url.replace("r2.cloudflarestorage.com", "R2.cloudflarestorage.com"),
        signed_url.replace(
            "r2.cloudflarestorage.com",
            "r2.cloudflarestorage.com.evil.example",
        ),
        signed_url.replace("r2.cloudflarestorage.com", "evil.r2.cloudflarestorage.com"),
        signed_url.replace("r2.cloudflarestorage.com", "r2.cloudflarestorage.com."),
        signed_url.replace("r2.cloudflarestorage.com", "eu.r2.cloudflarestorage.com"),
        signed_url.replace("r2.cloudflarestorage.com", "r2.dev"),
        signed_url.replace("r2.cloudflarestorage.com", "r2.cloudflarestorage.com:443"),
        signed_url.replace("r2.cloudflarestorage.com", "r2.cloudflarestorage.com:8443"),
        signed_url.replace("https://", "https://user:must-not-escape@"),
        signed_url.replace("https://", "https://@"),
        signed_url.replace("0123456789abcdef", "%30123456789abcdef"),
        format!("{signed_url}#must-not-escape"),
        signed_url.split_once('?').unwrap().0.to_string(),
        format!("{}?", signed_url.split_once('?').unwrap().0),
        "https://cdn.infishark.com/2.bin?X-Amz-Signature=must-not-escape".into(),
        "http://127.0.0.1:1/2.bin?X-Amz-Signature=must-not-escape".into(),
    ] {
        let (base, worker) =
            serve(|_| vec![(200, grant(metadata(url), Some(expiry)), String::new())]);
        assert_safe_error(
            Api::at(&base, "ctf_secret", "alice")
                .firmware_grant("gate")
                .unwrap_err(),
        );
        assert_eq!(worker.join().unwrap().len(), 1);
    }
    // A null expiry cannot disguise a signed URL as a public grant.
    let (base, worker) = serve(|_| {
        vec![(
            200,
            grant(
                metadata("https://cdn.infishark.com/2.bin?x-amz-signature=must-not-escape".into()),
                None,
            ),
            String::new(),
        )]
    });
    assert_safe_error(
        Api::at(&base, "ctf_secret", "alice")
            .firmware_grant("gate")
            .unwrap_err(),
    );
    worker.join().unwrap();
}

fn decoded_grant(url: String, expiry: i64) -> FirmwareGrant {
    let JsonObject(granted) =
        serde_json::from_slice::<JsonObject<FirmwareGrant>>(&grant(metadata(url), Some(expiry)))
            .unwrap();
    granted
}

#[test]
fn signed_grants_bind_the_canonical_bucket_challenge_and_version_path() {
    let expiry = future_expiry();
    let signed_url = signed_url_at(expiry - 300, 300);
    for path in [
        "/ctf/gate/2.bin",
        "/firmware-bucket/ctf/other/2.bin",
        "/firmware-bucket/ctf/gate/3.bin",
        "/firmware-bucket/ctf/gate/02.bin",
        "/firmware-bucket/ctf/gate/2.bin/",
        "/firmware-bucket/ctf/gate/2.bin/extra",
        "/firmware-bucket/ctf/%67ate/2.bin",
        "/firmware-bucket/ctf/gate%2F2.bin",
        "/firmware-bucket/ctf/gate/../gate/2.bin",
        "/firmware-bucket/ctf/gate/%2e%2e/gate/2.bin",
        "//ctf/gate/2.bin",
        "/x/ctf/gate/2.bin",
        "/UPPER/ctf/gate/2.bin",
        "/firmware..bucket/ctf/gate/2.bin",
        "/127.0.0.1/ctf/gate/2.bin",
        "/%66irmware-bucket/ctf/gate/2.bin",
        "/firmware-bucket/ctf/gate/2.bin%00",
    ] {
        let url = signed_url.replace("/firmware-bucket/ctf/gate/2.bin", path);
        let (base, worker) =
            serve(|_| vec![(200, grant(metadata(url), Some(expiry)), String::new())]);
        assert_safe_error(
            Api::at(&base, "ctf_secret", "alice")
                .firmware_grant("gate")
                .unwrap_err(),
        );
        assert_eq!(worker.join().unwrap().len(), 1);
    }
    for bucket in ["abc", "firmware.bucket", "firmware-bucket"] {
        let url = signed_url.replace("/firmware-bucket/", &format!("/{bucket}/"));
        decoded_grant(url, expiry).validate("gate").unwrap();
    }
}

fn replace_signed_query(url: &str, name: &str, replacement: Option<&str>) -> String {
    let mut parsed = Url::parse(url).unwrap();
    let fields: Vec<_> = parsed
        .query_pairs()
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect();
    parsed.set_query(None);
    for (key, value) in fields {
        if key == name {
            if let Some(replacement) = replacement {
                parsed.query_pairs_mut().append_pair(&key, replacement);
            }
        } else {
            parsed.query_pairs_mut().append_pair(&key, &value);
        }
    }
    parsed.into()
}

#[test]
fn signed_grants_require_all_six_unique_sigv4_fields_without_extras() {
    let now = 1767225600; // 2026-01-01T00:00:00Z
    let valid = signed_url_at(now, 300);
    for field in [
        "X-Amz-Algorithm",
        "X-Amz-Credential",
        "X-Amz-Date",
        "X-Amz-Expires",
        "X-Amz-SignedHeaders",
        "X-Amz-Signature",
    ] {
        for url in [
            replace_signed_query(&valid, field, None),
            replace_signed_query(&valid, field, Some("")),
            format!("{valid}&{field}=must-not-escape"),
            valid.replace(field, &field.to_ascii_lowercase()),
            valid.replace(field, &field.replacen("-", "%2D", 1)),
        ] {
            assert_safe_error(
                decoded_grant(url, now + 300)
                    .validate_at("gate", now)
                    .unwrap_err(),
            );
        }
    }
    for extra in [
        "&x-id=GetObject",
        "&X-Amz-Security-Token=must-not-escape",
        "&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD",
        "&extra=must-not-escape",
        "&",
        "&broken",
    ] {
        assert_safe_error(
            decoded_grant(format!("{valid}{extra}"), now + 300)
                .validate_at("gate", now)
                .unwrap_err(),
        );
    }
    for (field, value) in [
        ("X-Amz-Algorithm", "AWS4-HMAC-SHA1"),
        ("X-Amz-Credential", "must-not-escape"),
        ("X-Amz-Credential", "/20260101/auto/s3/aws4_request"),
        ("X-Amz-Credential", "KEY/20260102/auto/s3/aws4_request"),
        ("X-Amz-Credential", "KEY/20260101/us-east-1/s3/aws4_request"),
        ("X-Amz-Credential", "KEY/20260101/auto/ec2/aws4_request"),
        ("X-Amz-Credential", "KEY/20260101/auto/s3/wrong"),
        (
            "X-Amz-Credential",
            "KEY/20260101/auto/s3/aws4_request/extra",
        ),
        (
            "X-Amz-Credential",
            "KEY WITH SPACE/20260101/auto/s3/aws4_request",
        ),
        ("X-Amz-Date", "20260230T000000Z"),
        ("X-Amz-Date", "20260101T000000+0000"),
        ("X-Amz-Date", "20260101T240000Z"),
        ("X-Amz-Date", "20260101T000060Z"),
        ("X-Amz-Date", "20260101T000000z"),
        ("X-Amz-Expires", "0"),
        ("X-Amz-Expires", "301"),
        ("X-Amz-Expires", "-1"),
        ("X-Amz-Expires", "0300"),
        ("X-Amz-Expires", "300.0"),
        ("X-Amz-Expires", "9223372036854775807"),
        ("X-Amz-SignedHeaders", "host;authorization"),
        ("X-Amz-SignedHeaders", "Host"),
        ("X-Amz-Signature", "must-not-escape"),
        (
            "X-Amz-Signature",
            "ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        ),
    ] {
        let url = replace_signed_query(&valid, field, Some(value));
        assert_safe_error(
            decoded_grant(url, now + 300)
                .validate_at("gate", now)
                .unwrap_err(),
        );
    }
    decoded_grant(valid, now + 300)
        .validate_at("gate", now)
        .unwrap();
}

#[test]
fn grant_and_signature_expiry_limits_are_checked_at_download_time() {
    let now = 1767225600;
    for expiry in [i64::MIN, -1, 0, now, now + 601, i64::MAX] {
        let error = decoded_grant(signed_url_at(now, 300), expiry)
            .validate_at("gate", now)
            .unwrap_err();
        if expiry > now + 600 {
            assert_eq!(
                error.to_string(),
                "CTF firmware grant expiry exceeds ten minutes"
            );
        }
        assert_safe_error(error);
    }
    for (signed_at, lifetime, expiry) in [
        (now - 300, 300, now + 1),  // SigV4 itself has expired.
        (now + 61, 300, now + 300), // Future signing date outside clock tolerance.
        (now, 300, now + 301),      // Grant must not outlive the signed URL.
        (now, 301, now + 300),
    ] {
        assert_safe_error(
            decoded_grant(signed_url_at(signed_at, lifetime), expiry)
                .validate_at("gate", now)
                .unwrap_err(),
        );
    }
    for lifetime in [1, 300] {
        let granted = decoded_grant(signed_url_at(now, lifetime), now + lifetime);
        granted.validate_at("gate", now).unwrap();
        assert_safe_error(granted.validate_at("gate", now + lifetime).unwrap_err());
    }
    decoded_grant(signed_url_at(now + 60, 300), now + 360)
        .validate_at("gate", now)
        .unwrap();
    // Null-expiry free grants keep the existing public metadata URL and report.
    let public = metadata("https://cdn.infishark.com/ctf/gate/2.bin".into());
    let JsonObject(granted) =
        serde_json::from_slice::<JsonObject<FirmwareGrant>>(&grant(public.clone(), None)).unwrap();
    granted.validate_at("gate", now).unwrap();
    assert_eq!(granted.into_report(), public);
}

#[test]
fn sigv4_dates_use_real_utc_calendar_days_and_exact_format() {
    for (date, seconds) in [
        ("19700101T000000Z", 0),
        ("20000101T000000Z", 946684800),
        ("20000229T000000Z", 951782400),
        ("20260101T000000Z", 1767225600),
        ("20240229T235959Z", 1709251199),
        ("21000301T000000Z", 4107542400),
    ] {
        assert_eq!(sigv4_timestamp(date), Some(seconds));
        assert_eq!(aws_date(seconds), date);
    }
    for date in [
        "",
        "20260101",
        "20260101T000000z",
        "19691231T235959Z",
        "21000229T000000Z",
        "20261301T000000Z",
        "20260100T000000Z",
        "20260101T006000Z",
        "20260101T000060Z",
        "\u{ff12}\u{ff10}\u{ff12}\u{ff16}0101T000000Z",
    ] {
        assert_eq!(sigv4_timestamp(date), None);
    }
}

#[test]
fn explicit_images_still_require_membership_for_backend_issuance() {
    let file = DownloadedFirmware::new().unwrap();
    std::fs::write(&file.bin, IMAGE).unwrap();
    let spec = resolve_start("gate", Some(&file.bin), false).unwrap();
    let (base, worker) = serve(|_| {
        vec![(
            403,
            format!("provider-body {SIGNED_URL}").into_bytes(),
            String::new(),
        )]
    });
    let prepared = prepare_start(&spec, false, &opts(base)).unwrap();
    let error = prepared
        .api
        .as_ref()
        .unwrap()
        .issue("gate", &[9; 32])
        .unwrap_err();
    assert_eq!(error.to_string(), "CTF issue requires an active membership");
    assert_safe_error(error);
    let requests = worker.join().unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("POST /v1/challenges/gate/issue "));
    assert!(
        requests[0]
            .to_ascii_lowercase()
            .contains("authorization: bearer player-secret")
    );
    assert!(file.bin.exists());
}

#[test]
fn signed_downloads_never_redirect_or_send_player_credentials() {
    // Test signed downloads over loopback after validating canonical grants
    // separately.
    for status in [301, 302, 303, 307, 308] {
        let (base, worker) = serve(|base| {
            vec![(
                status,
                b"provider-body".to_vec(),
                format!("Location: {base}/leak?X-Amz-Signature=must-not-escape\r\n"),
            )]
        });
        let url = firmware_url(&format!("{base}/2.bin?X-Amz-Signature=must-not-escape")).unwrap();
        let error = download_firmware_from(&metadata(SIGNED_URL.into()), url, false).unwrap_err();
        assert_eq!(
            error.to_string(),
            "signed firmware redirects are not allowed"
        );
        assert_safe_error(error);
        let requests = worker.join().unwrap();
        assert_eq!(requests.len(), 1);
        let request = requests[0].to_ascii_lowercase();
        assert!(request.starts_with("get /2.bin?"));
        for header in ["authorization:", "x-user:", "x-ctf-token:"] {
            assert!(!request.contains(header));
        }
    }
    let origin = firmware_url(SIGNED_URL).unwrap();
    assert_eq!(
        firmware_redirect(&origin, "/other.bin")
            .unwrap_err()
            .to_string(),
        "signed firmware redirects are not allowed"
    );
    let public = firmware_url("https://cdn.infishark.com/2.bin").unwrap();
    assert_safe_error(firmware_redirect(&public, SIGNED_URL).unwrap_err());
}

#[test]
fn artifact_and_grant_transport_and_stream_errors_do_not_leak_urls() {
    // Avoid releasing an ephemeral port that another parallel test may reuse.
    let unreachable = "http://127.0.0.1:0";
    let url = firmware_url(&format!(
        "{unreachable}/2.bin?X-Amz-Signature=must-not-escape"
    ))
    .unwrap();
    assert_safe_error(
        download_firmware_from(&metadata(SIGNED_URL.into()), url, false).unwrap_err(),
    );
    assert_safe_error(
        Api::at(
            &format!("{unreachable}/must-not-escape"),
            "ctf_secret",
            "alice",
        )
        .firmware_grant("gate")
        .unwrap_err(),
    );
    for status in [401, 403, 404, 503] {
        let (base, worker) = serve(|_| {
            vec![(
                status,
                format!("provider-body {SIGNED_URL}").into_bytes(),
                String::new(),
            )]
        });
        let url = firmware_url(&format!("{base}/2.bin?X-Amz-Signature=must-not-escape")).unwrap();
        assert_safe_error(
            download_firmware_from(&metadata(SIGNED_URL.into()), url, false).unwrap_err(),
        );
        worker.join().unwrap();
    }
    struct LeakyStream;
    impl Read for LeakyStream {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other(SIGNED_URL))
        }
    }
    let download = DownloadedFirmware::new().unwrap();
    let dir = download.dir.clone();
    assert_safe_error(
        store_firmware(&metadata(SIGNED_URL.into()), LeakyStream, download).unwrap_err(),
    );
    assert!(!dir.exists());
}

#[test]
fn local_override_skips_grants_and_local_mode_skips_api() {
    let file = DownloadedFirmware::new().unwrap();
    std::fs::write(&file.bin, IMAGE).unwrap();
    let spec = resolve_start("gate", Some(&file.bin), false).unwrap();
    // An unreachable API proves preparation of an override makes no requests.
    let prepared = prepare_start(&spec, false, &opts("http://127.0.0.1:1".into())).unwrap();
    assert_eq!(prepared.bin, file.bin);
    assert!(prepared._download.is_none());
    assert!(prepared.firmware.is_none());
    assert!(prepared.api.is_some());
    let local = prepare_start(
        &spec,
        true,
        &ApiOpts {
            url: Some("invalid".into()),
            token: None,
            user: None,
        },
    )
    .unwrap();
    assert_eq!(local.bin, file.bin);
    assert!(local.api.is_none());
    assert!(file.bin.exists());
}

#[test]
fn relative_redirects_work_without_player_headers() {
    let (base, worker) = serve(|_| {
        vec![
            (302, Vec::new(), "Location: /final.bin\r\n".into()),
            (200, IMAGE.to_vec(), String::new()),
        ]
    });
    let image = download_firmware(&metadata(format!("{base}/2.bin"))).unwrap();
    assert_eq!(std::fs::read(&image.bin).unwrap(), IMAGE);
    for request in worker.join().unwrap() {
        let request = request.to_ascii_lowercase();
        assert!(!request.contains("authorization:"));
        assert!(!request.contains("x-user:"));
    }
}

#[test]
fn unsafe_redirects_and_redirect_loops_are_rejected() {
    let (base, worker) = serve(|_| {
        vec![(
            302,
            Vec::new(),
            "Location: http://example.com/2.bin\r\n".into(),
        )]
    });
    let err = download_firmware(&metadata(format!("{base}/2.bin")))
        .unwrap_err()
        .to_string();
    assert!(err.contains("HTTPS"), "{err}");
    assert_eq!(worker.join().unwrap().len(), 1);
    let (base, worker) = serve(|_| {
        (0..6)
            .map(|_| (302, Vec::new(), "Location: /2.bin\r\n".into()))
            .collect()
    });
    let err = download_firmware(&metadata(format!("{base}/2.bin")))
        .unwrap_err()
        .to_string();
    assert!(err.contains("too many firmware redirects"), "{err}");
    assert_eq!(worker.join().unwrap().len(), 6);
}

#[test]
fn http_errors_and_truncated_streams_fail() {
    for status in [404, 500, 206] {
        let (base, worker) = serve(|_| vec![(status, b"unavailable".to_vec(), String::new())]);
        assert!(download_firmware(&metadata(format!("{base}/2.bin"))).is_err());
        worker.join().unwrap();
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/2.bin", listener.local_addr().unwrap());
    let worker = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        assert!(socket.read(&mut buf).unwrap() > 0);
        write!(
            socket,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\nshort",
            IMAGE.len()
        )
        .unwrap();
    });
    assert!(download_firmware(&metadata(url)).is_err());
    worker.join().unwrap();
}

#[test]
fn hints_are_public_selected_and_validate_response() {
    let (base, worker) = serve(|_| {
        vec![(
            200,
            br#"{"challenge":"gate","level":2,"total":3,"text":"Reverse byte order."}"#.to_vec(),
            String::new(),
        )]
    });
    let api = Api {
        url: base,
        token: Some("player-secret".into()),
        user: "alice".into(),
    };
    let hint = api.hint("gate", 2).unwrap();
    assert_eq!(hint.text, "Reverse byte order.");
    assert_eq!(hint.level, 2);
    let request = worker.join().unwrap().pop().unwrap().to_ascii_lowercase();
    assert!(request.starts_with("get /v1/challenges/gate/hints/2 "));
    assert!(!request.contains("authorization:"));
    assert!(!request.contains("x-user:"));
    assert!(api.hint("../gate", 1).is_err());
    assert!(api.hint("gate", 0).is_err());
    let (base, worker) = serve(|_| {
        vec![(
            404,
            b"private-provider-body available levels: 1-3".to_vec(),
            String::new(),
        )]
    });
    let api = Api {
        url: base,
        token: None,
        user: "alice".into(),
    };
    let error = api.hint("gate", 4).unwrap_err().to_string();
    assert!(error.contains("HTTP 404") && error.contains("earlier level"));
    assert!(!error.contains("private-provider-body"));
    worker.join().unwrap();
    let (base, worker) = serve(|_| {
        vec![(
            200,
            br#"{"challenge":"gate","level":3,"total":3,"text":"Wrong level."}"#.to_vec(),
            String::new(),
        )]
    });
    let api = Api {
        url: base,
        token: None,
        user: "alice".into(),
    };
    assert!(
        api.hint("gate", 1)
            .unwrap_err()
            .to_string()
            .contains("invalid hint response")
    );
    worker.join().unwrap();
}

#[test]
fn failed_verification_removes_partial_files() {
    for body in [
        vec![0; IMAGE.len()],
        IMAGE[..IMAGE.len() - 1].to_vec(),
        [IMAGE, b"extra"].concat(),
    ] {
        let download = DownloadedFirmware::new().unwrap();
        let dir = download.dir.clone();
        let firmware = metadata("https://cdn.infishark.com/2.bin".into());
        assert!(store_firmware(&firmware, body.as_slice(), download).is_err());
        assert!(!dir.exists());
    }
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("interrupted stream"))
        }
    }
    let download = DownloadedFirmware::new().unwrap();
    let dir = download.dir.clone();
    assert!(
        store_firmware(
            &metadata("https://cdn.infishark.com/2.bin".into()),
            Broken,
            download
        )
        .is_err()
    );
    assert!(!dir.exists());
}

#[test]
fn https_redirects_cannot_downgrade_even_to_loopback() {
    let origin = firmware_url("https://cdn.infishark.com/ctf/gate/2.bin").unwrap();
    assert!(
        firmware_redirect(&origin, "http://127.0.0.1:1234/2.bin")
            .unwrap_err()
            .to_string()
            .contains("cannot downgrade")
    );
    assert!(firmware_redirect(&origin, "http://example.com/2.bin").is_err());
    assert_eq!(
        firmware_redirect(&origin, "../3.bin").unwrap().as_str(),
        "https://cdn.infishark.com/ctf/3.bin"
    );
    assert!(firmware_redirect(&origin, "https://user:secret@cdn.infishark.com/2.bin").is_err());
}

#[test]
fn api_does_not_follow_redirects_with_player_identity() {
    let (base, worker) = serve(|_| {
        vec![(
            302,
            Vec::new(),
            "Location: http://127.0.0.1:1/leak\r\n".into(),
        )]
    });
    let api = Api {
        url: base,
        token: Some("player-secret".into()),
        user: "alice".into(),
    };
    assert_eq!(
        api.challenges().unwrap_err().to_string(),
        "CTF server HTTP 302"
    );
    let request = worker.join().unwrap().pop().unwrap().to_ascii_lowercase();
    assert!(!request.contains("authorization:"));
    assert!(!request.contains("x-user:"));
    let (base, worker) = serve(|_| {
        vec![(
            307,
            Vec::new(),
            "Location: http://127.0.0.1:1/leak\r\n".into(),
        )]
    });
    let api = Api {
        url: base,
        token: Some("player-secret".into()),
        user: "alice".into(),
    };
    assert_eq!(
        api.issue("gate", &[9; 32]).unwrap_err().to_string(),
        "CTF issue HTTP 307"
    );
    assert_eq!(worker.join().unwrap().len(), 1);
}
