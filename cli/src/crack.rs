//! Hand a hashcat 22000 file to hashcat and report the recovered password.
//! Shared by `wifi handshake --crack` and a future `wifi crack`.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};

const COMMON_WORDLISTS: [&str; 1] = ["/usr/share/wordlists/rockyou.txt"];

pub fn run(hashfile: &str, wordlist: Option<&str>) {
    if !hashcat_available() {
        println!("  --crack needs hashcat on PATH; install it or crack {hashfile} yourself");
        return;
    }
    let Some(wl) = resolve_wordlist(wordlist) else {
        println!("  --crack needs --wordlist <path> (e.g. rockyou.txt)");
        return;
    };
    println!("  cracking {hashfile} with hashcat ({wl})...");
    match crack_22000(Path::new(hashfile), Path::new(&wl)) {
        Ok(Some(pw)) => println!("  password: {pw}"),
        Ok(None) => println!("  not found in {wl}"),
        Err(e) => println!("  hashcat error: {e:#}"),
    }
}

pub fn hashcat_available() -> bool {
    Command::new("hashcat").arg("--version").output().is_ok()
}

fn resolve_wordlist(wordlist: Option<&str>) -> Option<String> {
    if let Some(w) = wordlist {
        return Some(w.to_string());
    }
    COMMON_WORDLISTS
        .iter()
        .find(|p| Path::new(p).exists())
        .map(|p| p.to_string())
}

pub fn crack_22000(hashfile: &Path, wordlist: &Path) -> Result<Option<String>> {
    let status = Command::new("hashcat")
        .args(["-m", "22000"])
        .arg(hashfile)
        .arg(wordlist)
        .status()
        .context("failed to launch hashcat")?;
    if !matches!(status.code(), Some(0 | 1)) {
        bail!("hashcat exited with {status}"); // 0=cracked, 1=exhausted
    }
    let out = Command::new("hashcat")
        .args(["-m", "22000", "--show"])
        .arg(hashfile)
        .output()
        .context("failed to run hashcat --show")?;
    let show = String::from_utf8_lossy(&out.stdout);
    Ok(show.lines().find_map(parse_cracked).map(str::to_string))
}

// A hashcat 22000 --show line is `<hashline>:<password>`; the star-delimited hex
// hashline has no colon, so the first colon is the separator.
fn parse_cracked(line: &str) -> Option<&str> {
    line.split_once(':')
        .map(|(_, pw)| pw)
        .filter(|pw| !pw.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_password_after_the_first_colon() {
        assert_eq!(
            parse_cracked("WPA*01*ab*cd*ef*6869***:hunter2"),
            Some("hunter2")
        );
        assert_eq!(parse_cracked("hash:a:b:c"), Some("a:b:c")); // colons in the password
        assert_eq!(parse_cracked("nocolon"), None);
        assert_eq!(parse_cracked("hash:"), None);
    }
}
