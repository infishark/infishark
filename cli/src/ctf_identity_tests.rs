//! Offline identity and challenge-bound provisioning regressions.
use super::*;

fn hello(slug: &str) -> serde_json::Value {
    serde_json::json!({"proto": 2, "pub": hex::encode_lower(&[9; 32]), "challenge": slug})
}

#[test]
fn load_cli_accepts_auto_detect_or_optional_assertion() {
    use clap::Parser;
    for (argv, expected) in [
        (vec!["infishark", "ctf", "load"], None),
        (vec!["infishark", "ctf", "load", "gate"], Some("gate")),
    ] {
        let cli = crate::Cli::try_parse_from(argv).unwrap();
        match cli.command.unwrap() {
            crate::Command::Ctf {
                action: crate::CtfCmd::Load { slug, .. },
            } => {
                assert_eq!(slug.as_deref(), expected);
            }
            _ => panic!("wrong command"),
        }
    }
}

#[test]
fn hello_detects_identity_without_fallback_and_checks_assertion() {
    let valid = hello("gate");
    assert_eq!(box_hello(&valid, None).unwrap().slug, "gate");
    box_hello(&valid, Some("gate")).unwrap();
    let error = box_hello(&valid, Some("nameplate"))
        .unwrap_err()
        .to_string();
    assert!(error.contains("challenge mismatch"));
    assert!(error.contains("no flag issued or loaded"));
    for slug in [
        "unknown",
        "",
        "Gate",
        "_gate",
        "-gate",
        "gate/other",
        "gate\n",
        "\u{e9}",
    ] {
        let error = box_hello(&hello(slug), None).unwrap_err().to_string();
        assert!(error.contains("reflash required"));
        assert!(!error.contains(slug) || slug.is_empty() || slug == "unknown");
    }
    for field in ["proto", "challenge", "pub"] {
        let mut missing = valid.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(
            box_hello(&missing, None)
                .unwrap_err()
                .to_string()
                .contains("reflash required")
        );
    }
    for value in [
        serde_json::json!(1),
        serde_json::json!(true),
        serde_json::json!("2"),
        serde_json::json!(null),
    ] {
        let mut legacy = valid.clone();
        legacy["proto"] = value;
        assert!(
            box_hello(&legacy, Some("gate"))
                .unwrap_err()
                .to_string()
                .contains("reflash required")
        );
    }
    for field in ["reset", "ready"] {
        for value in [serde_json::json!(true), serde_json::json!(false)] {
            let mut optional = valid.clone();
            optional[field] = value;
            box_hello(&optional, None).unwrap();
        }
        for value in [
            serde_json::json!(null),
            serde_json::json!(1),
            serde_json::json!("true"),
        ] {
            let mut invalid = valid.clone();
            invalid[field] = value;
            assert!(box_hello(&invalid, None).is_err());
        }
    }
}

#[test]
fn canonical_slug_boundaries() {
    for slug in ["a", "0", "a-b_0", &"a".repeat(64)] {
        check_slug(slug).unwrap();
    }
    for slug in ["", "A", "_a", "-a", "a.b", " a", "a ", &"a".repeat(65)] {
        assert!(check_slug(slug).is_err());
    }
}

#[test]
fn exact_aad_wrong_slug_and_legacy_rejected_with_preserved_slot() {
    let sk = StaticSecret::from([0x77; 32]);
    let pk = PublicKey::from(&sk).to_bytes();
    let old_flag = b"flag{already-loaded}".to_vec();
    let load = seal(&pk, "gate", &old_flag).unwrap();
    assert_eq!(load_aad("gate").unwrap(), b"infishark-ctf:2:gate");
    let mut slot = unseal(&sk, "gate", &load).unwrap();
    let wrong_slug = seal(&pk, "nameplate", b"flag{wrong-challenge}").unwrap();
    if let Ok(flag) = unseal(&sk, "gate", &wrong_slug) {
        slot = flag;
    }
    assert_eq!(slot, old_flag);
    let key = sk
        .diffie_hellman(&PublicKey::from(load.host_pub))
        .to_bytes();
    let cipher = Aes256Gcm::new((&key).into());
    for aad in [
        b"".as_slice(),
        b"infishark-ctf:1:gate",
        b"infishark-ctf:2:gate\0",
        b"infishark-ctf:2:GATE",
    ] {
        assert!(
            cipher
                .decrypt(
                    Nonce::from_slice(&load.nonce),
                    Payload { msg: &load.ct, aad }
                )
                .is_err()
        );
    }
}

#[test]
fn local_flag_byte_boundaries() {
    for length in [1, 95] {
        let flag = vec![b'x'; length];
        let sk = StaticSecret::from([0x77; 32]);
        let pk = PublicKey::from(&sk).to_bytes();
        let load = seal(&pk, "gate", &flag).unwrap();
        assert_eq!(unseal(&sk, "gate", &load).unwrap(), flag);
    }
    for length in [0, 96] {
        assert!(seal(&[9; 32], "gate", &vec![b'x'; length]).is_err());
    }
}

#[test]
fn load_recheck_requires_both_original_boot_key_and_slug() {
    let before = BoxHello {
        key: [9; 32],
        slug: "gate".into(),
    };
    let same = BoxHello {
        key: before.key,
        slug: before.slug.clone(),
    };
    check_load_identity(&before, &same).unwrap();
    for after in [
        BoxHello {
            key: [8; 32],
            slug: before.slug.clone(),
        },
        BoxHello {
            key: before.key,
            slug: "nameplate".into(),
        },
        BoxHello {
            key: [8; 32],
            slug: "nameplate".into(),
        },
    ] {
        let error = check_load_identity(&before, &after)
            .unwrap_err()
            .to_string();
        assert!(error.contains("changed before LOAD"));
        assert!(!error.contains("no flag issued"));
        assert!(!error.contains(&hex::encode_lower(&before.key)));
        assert!(!error.contains(&hex::encode_lower(&after.key)));
    }
}

#[test]
fn reset_must_preserve_challenge_identity() {
    let before = BoxHello {
        key: [1; 32],
        slug: "gate".into(),
    };
    let mut after = hello("nameplate");
    after["reset"] = serde_json::json!(true);
    after["ready"] = serde_json::json!(true);
    assert!(
        check_reset_return(&before, true, &after)
            .unwrap_err()
            .to_string()
            .contains("different challenge identity")
    );
}
