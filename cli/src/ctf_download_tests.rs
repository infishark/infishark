use super::*;
use std::net::TcpListener;
use std::thread::JoinHandle;

const IMAGE: &[u8] = b"\xe9CTF firmware\0\xff";

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

fn decoded_grant(url: String, expiry: i64) -> FirmwareGrant {
    let JsonObject(granted) =
        serde_json::from_slice::<JsonObject<FirmwareGrant>>(&grant(metadata(url), Some(expiry)))
            .unwrap();
    granted
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
