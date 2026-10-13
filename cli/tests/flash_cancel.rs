#![cfg(unix)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let nonce = rand::random::<u64>();
        let dir = std::env::temp_dir().join(format!("infishark-flash-cancel-{nonce:016x}"));
        std::fs::create_dir(&dir).unwrap();
        Self(dir)
    }

    fn command(&self, script: &str) -> Command {
        let tool = self.0.join("espflash");
        std::fs::write(&tool, format!("#!/bin/sh\n{script}\n")).unwrap();
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_infishark"));
        command
            .env("INFISHARK_ESPTOOL", tool)
            .env("INFISHARK_FLASH_TEST_MARKER", self.0.join("flasher-calls"))
            .env("XDG_CONFIG_HOME", self.0.join("config"))
            .env_remove("INFISHARK_CTF_URL")
            .env_remove("CTF_URL")
            .env_remove("INFISHARK_CTF_TOKEN")
            .env_remove("CTF_TOKEN")
            .env_remove("ISHARK_DEBUG_SERIAL")
            .args(["--port", "/tmp/infishark-cancel-mock-only"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        command
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn cancel_during_grant_does_not_erase_or_write_flash() {
    let fixture = Fixture::new();
    let marker = fixture.0.join("flasher-calls");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let image = b"synthetic firmware";
    let grant = serde_json::json!({
        "challenge": "gate",
        "firmware": {
            "version": 1,
            "url": format!("{url}/image"),
            "sha256": format!("{:x}", Sha256::digest(image)),
            "size_bytes": image.len(),
        },
        "expires_at": null,
    })
    .to_string();
    let (started_tx, started_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut served = 0;
        while served < 2 && Instant::now() < deadline {
            let (mut stream, _) = match listener.accept() {
                Ok(connection) => connection,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(e) => panic!("{e}"),
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            let mut buf = [0; 4096];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                let count = stream.read(&mut buf).unwrap();
                assert!(count > 0);
                request.extend_from_slice(&buf[..count]);
            }
            let body: &[u8] = if served == 0 {
                started_tx.send(()).unwrap();
                std::thread::sleep(Duration::from_millis(300));
                grant.as_bytes()
            } else {
                image
            };
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(body).unwrap();
            served += 1;
        }
    });
    let child = fixture
        .command("echo called >> \"$INFISHARK_FLASH_TEST_MARKER\"")
        .args([
            "ctf",
            "start",
            "gate",
            "--yes",
            "--url",
            &url,
            "--token",
            "synthetic-token",
        ])
        .spawn()
        .unwrap();
    started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGINT) }, 0);
    let output = child.wait_with_output().unwrap();
    worker.join().unwrap();
    assert_eq!(output.status.code(), Some(130));
    assert!(!marker.exists(), "cancelled start invoked the flasher");
}

#[test]
fn cancel_after_ota_erase_does_not_write_the_image() {
    let fixture = Fixture::new();
    let marker = fixture.0.join("flasher-calls");
    let image = fixture.0.join("firmware.bin");
    std::fs::write(&image, b"synthetic firmware").unwrap();
    let output = fixture
        .command("echo called >> \"$INFISHARK_FLASH_TEST_MARKER\"\nkill -INT \"$PPID\"")
        .args(["flash", "write"])
        .arg(image)
        .arg("--yes")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(130));
    assert_eq!(std::fs::read_to_string(marker).unwrap().lines().count(), 1);
}
