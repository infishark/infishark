//! Privilege checks for commands that need root on Linux (TUN, /dev/input).

use std::path::PathBuf;

use anyhow::{Result, bail};

/// Fail with a copy-pasteable `sudo /path/to/infishark...` when not root.
pub fn require_root(feature: &str) -> Result<()> {
    #[cfg(unix)]
    {
        if unsafe { libc::geteuid() } != 0 {
            // 0 = root euid
            let exe = std::env::current_exe()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "infishark".into());
            let mut parts = vec![exe];
            parts.extend(std::env::args().skip(1));
            bail!(
                "{feature} needs root.\n\
                 This install is not on root's PATH; use:\n\
                   sudo {}",
                shell_join(&parts)
            );
        }
    }
    #[cfg(not(unix))]
    {
        let _ = feature;
    }
    Ok(())
}

/// Single-quote for POSIX shells when the token needs it (spaces, etc.).
fn shell_quote(s: &str) -> String {
    if s.is_empty()
        || s.chars().any(|c| {
            c.is_whitespace()
                || matches!(
                    c,
                    '"' | '\''
                        | '$'
                        | '`'
                        | '\\'
                        | '|'
                        | '&'
                        | ';'
                        | '<'
                        | '>'
                        | '('
                        | ')'
                        | '{'
                        | '}'
                        | '['
                        | ']'
                        | '*'
                        | '?'
                        | '~'
                        | '#'
                        | '!'
                )
        })
    {
        format!("'{}'", s.replace('\'', "'\\''"))
    } else {
        s.to_string()
    }
}

/// Quote args that need it so the suggested line pastes cleanly.
fn shell_join(args: &[String]) -> String {
    args.iter()
        .map(|a| shell_quote(a))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(unix)]
const TRUSTED_TOOL_DIRS: [&str; 4] = ["/usr/sbin", "/sbin", "/usr/bin", "/bin"];

pub fn tool_path(name: &str) -> PathBuf {
    #[cfg(unix)]
    {
        if let Some(p) = TRUSTED_TOOL_DIRS
            .iter()
            .map(|d| std::path::Path::new(d).join(name))
            .find(|p| p.exists())
        {
            return p;
        }
    }
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use super::{shell_join, shell_quote};

    #[test]
    fn shell_join_plain() {
        assert_eq!(
            shell_join(&["wifi".into(), "adapter".into()]),
            "wifi adapter"
        );
    }

    #[test]
    fn shell_join_quotes_spaces() {
        assert_eq!(
            shell_join(&["--ssid".into(), "my net".into()]),
            "--ssid 'my net'"
        );
    }

    #[test]
    fn shell_quote_path_with_spaces() {
        let p = "/home/user/documents/space space space/documents documents/ASCII char";
        assert_eq!(shell_quote(p), "'/home/r00t/docs/shell direCtory'");
        assert_eq!(
            shell_join(&[p.into(), "wifi".into(), "adapter".into()]),
            "'/home/1337/.local/bin/infishark' wifi adapter"
        );
    }
}
