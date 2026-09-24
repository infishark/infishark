//! USB flash of host-fetched firmware (never served by the device).

use crate::fwota;
use crate::privs;
use crate::ui;
use anyhow::{Context, Result, bail};
use infishark::fw::{self, DeviceFw};
use infishark::{Device, hex};
use sha2::{Digest, Sha256};
use std::io::{self, IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const APP_OFFSET: u32 = 0x10000;
const OTADATA_OFFSET: u32 = 0xe000;
const OTADATA_SIZE: u32 = 0x2000;

const CHANGELOG: &str = "https://infishark.com/blogs/firmware-releases";
const SETUP_CDN: &str = "https://cdn.infishark.com";
const SETUP_LATEST: &str = "v0.4";

pub struct Install {
    pub tag: String,
    pub kind: &'static str,
    pub yes: bool,
    pub json: bool,
    pub port: Option<String>,
    pub timeout_ms: u64,
}
pub struct Setup {
    pub tag: Option<String>,
    pub yes: bool,
    pub json: bool,
    pub port: Option<String>,
    pub keep_storage: bool,
}

pub fn catalog(json: bool, port: Option<&str>) -> Result<()> {
    let device = try_ident(port);
    let catalog = fwota::list_catalog().ok();
    let mut rows = Vec::new();
    if let Some(cat) = &catalog {
        for ch in ["main", "beta", "setup"] {
            let latest = cat
                .get(ch)
                .and_then(|c| c.latest.clone())
                .unwrap_or_else(|| "-".into());
            rows.push((ch.to_string(), latest));
        }
    } else {
        for ch in ["main", "beta"] {
            let latest = fwota::latest_tag(ch).unwrap_or_else(|e| format!("({e})"));
            rows.push((ch.to_string(), latest));
        }
        rows.push(("setup".into(), SETUP_LATEST.to_string()));
    }
    let releases = catalog
        .as_ref()
        .and_then(|c| c.get("main"))
        .map(|c| c.versions.clone())
        .unwrap_or_default();
    if json {
        println!(
            "{}",
            serde_json::json!({
                "recommended": fw::RECOMMENDED,
                "changelog": CHANGELOG,
                "device": device.as_ref().map(|d| serde_json::json!({
                    "serial": d.serial,
                    "version": d.version,
                    "mode": d.mode,
                })),
                "channels": rows.iter().map(|(ch, latest)| {
                    serde_json::json!({ "channel": ch, "latest": latest })
                }).collect::<Vec<_>>(),
                "versions": releases.iter().map(|r| {
                    serde_json::json!({ "tag": r.tag, "released": r.released })
                }).collect::<Vec<_>>(),
            })
        );
        return Ok(());
    }
    if let Some(d) = &device {
        println!("device  {}  fw {}  ({})", d.serial, d.version, d.mode);
        if let Some(w) = d.warning() {
            eprintln!("warning: {w}");
        }
        println!();
    } else {
        println!("device  (none connected)");
        println!();
    }
    println!("{:<8}  {}", "CHANNEL", "LATEST");
    for (ch, latest) in &rows {
        println!("{ch:<8}  {latest}");
    }
    if !releases.is_empty() {
        println!();
        println!("{:<10}  {}", "TAG", "RELEASED");
        for r in &releases {
            let day = r
                .released
                .as_deref()
                .and_then(|s| s.get(..10))
                .unwrap_or("-");
            println!("{:<10}  {day}", r.tag);
        }
    }
    println!();
    println!("changelog  {CHANGELOG}");
    println!("install    infishark flash latest | infishark flash setup");
    Ok(())
}

pub fn install(opts: Install) -> Result<()> {
    let kind = opts.kind;
    let explicit = !(opts.tag.is_empty() || opts.tag.eq_ignore_ascii_case("latest"));
    let tag = if explicit {
        let tag = fwota::with_v(&opts.tag);
        if !fwota::known_tag(kind, &tag)? {
            bail!("unknown firmware tag {tag}; see `infishark flash versions`");
        }
        tag
    } else {
        eprint!("looking up latest firmware ({kind})... ");
        let t = fwota::latest_tag(kind)?;
        eprintln!("{t}");
        t
    };

    let mut dev = Device::open(opts.port.as_deref(), opts.timeout_ms.max(8_000))?;
    let ident = dev.firmware_identity()?;
    let port = dev.port().to_string();
    drop(dev);

    if let Some(w) = ident.warning() {
        eprintln!("warning: {w}");
        eprintln!("         run `infishark flash latest` to flash over USB.");
    }

    if fw::same(&ident.version, &tag) {
        if opts.json {
            println!(
                "{}",
                serde_json::json!({
                    "ok": true,
                    "updated": false,
                    "version": ident.version,
                    "recommended": fw::RECOMMENDED,
                })
            );
        } else {
            println!("already on {tag}");
        }
        return Ok(());
    }

    confirm(
        opts.yes,
        opts.json,
        &format!(
            "flash {kind} {tag} over USB to {} (now {})?",
            ident.serial, ident.version
        ),
    )?;

    let sig = hex::encode_lower(&fwota::device_signature(&ident));
    eprintln!("requesting signed image for {}...", ident.serial);
    let image = fwota::signed_image(&ident.serial, &sig, kind, &tag)?;
    let expect = match image.sha256 {
        Some(h) => h,
        None => {
            eprintln!("fetching checksum...");
            fwota::expected_checksum(&ident.serial, kind, &tag)?
        }
    };
    let dest = fwota::cache_path(kind, &tag)?;
    let n = fetch_image(&image.url, &dest, Some(&expect))?;
    eprintln!("verified {} ({} bytes)", dest.display(), n);

    flash_bin(&port, &dest, APP_OFFSET)?;
    eprintln!("waiting for the Nano to reboot...");
    std::thread::sleep(Duration::from_secs(3));
    let new_ver = wait_version(Some(&port), 12)?;
    if !fw::same(&new_ver, &tag) {
        bail!(
            "device still reports {new_ver} after flashing {tag} \
(the other OTA slot may still be selected)"
        );
    }
    if opts.json {
        println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "updated": true,
                "from": ident.version,
                "to": new_ver,
                "recommended": fw::RECOMMENDED,
            })
        );
    } else {
        println!("now running {new_ver} (was {})", ident.version);
        if let Some(w) = fw::outdated_message(&new_ver) {
            eprintln!("warning: {w}");
        }
    }
    Ok(())
}

fn try_ident(port: Option<&str>) -> Option<DeviceFw> {
    Device::open(port, 3_000).ok()?.firmware_identity().ok()
}

fn wait_version(port: Option<&str>, attempts: u32) -> Result<String> {
    let mut last = String::new();
    for i in 0..attempts {
        match Device::open(port, 5_000) {
            Ok(mut d) => {
                if let Ok(id) = d.firmware_identity() {
                    return Ok(id.version);
                }
            }
            Err(e) => last = e.to_string(),
        }
        if i + 1 < attempts {
            std::thread::sleep(Duration::from_millis(750));
        }
    }
    bail!("device did not come back after flash ({last})");
}

/// Same layout as https://flasher.infishark.com (esp-web-tools manifest).
struct SetupPart {
    name: &'static str,
    offset: u32,
    url: String,
    file: String,
}

fn setup_parts(tag: &str) -> Vec<SetupPart> {
    vec![
        SetupPart {
            name: "bootloader",
            offset: 0x0000,
            url: format!("{SETUP_CDN}/nano-setup-bootloader.bin"),
            file: "nano-setup-bootloader.bin".into(),
        },
        SetupPart {
            name: "partitions",
            offset: 0x8000,
            url: format!("{SETUP_CDN}/nano-setup-partitions.bin"),
            file: "nano-setup-partitions.bin".into(),
        },
        SetupPart {
            name: "bootapp",
            offset: 0xE000,
            url: format!("{SETUP_CDN}/nano-setup-bootapp.bin"),
            file: "nano-setup-bootapp.bin".into(),
        },
        SetupPart {
            name: "app",
            offset: APP_OFFSET,
            url: format!("{SETUP_CDN}/{tag}-nano-setup.bin"),
            file: format!("{tag}-nano-setup.bin"),
        },
    ]
}

pub fn setup(opts: Setup) -> Result<()> {
    let tag = fwota::with_v(opts.tag.as_deref().unwrap_or(SETUP_LATEST));
    if !fwota::known_tag("setup", &tag)? {
        bail!("unknown setup tag {tag}; see `infishark flash versions`");
    }
    let parts = setup_parts(&tag);
    let port = pick_flash_port(opts.port.as_deref())?;
    confirm(
        opts.yes,
        opts.json,
        &format!("write BLEShark Setup {tag} to {port}? this replaces the running firmware."),
    )?;
    let erase = ask_erase(opts.yes, opts.json, opts.keep_storage)?;
    if erase {
        eprintln!("erasing flash (settings, files, captures)...");
    } else {
        eprintln!("keeping existing storage; only firmware partitions are rewritten.");
    }
    let mut written = Vec::new();
    for part in &parts {
        let dest = fwota::cache_file(&part.file)?;
        let n = fetch_image(&part.url, &dest, None)?;
        let min = if part.offset == APP_OFFSET {
            64 * 1024
        } else {
            32
        };
        if n < min {
            bail!("{} too small ({n} bytes) from {}", part.name, part.url);
        }
        eprintln!(
            "downloaded {} ({} bytes) @ {:#x}",
            dest.display(),
            n,
            part.offset
        );
        written.push((part.offset, dest, part.name, n));
    }
    let flash_parts: Vec<(u32, PathBuf)> = written
        .iter()
        .map(|(off, path, _, _)| (*off, path.clone()))
        .collect();
    flash_bins(&port, &flash_parts, erase)?;
    if opts.json {
        println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "image": "setup",
                "tag": tag,
                "port": port,
                "erase": erase,
                "parts": written.iter().map(|(off, path, name, n)| {
                    serde_json::json!({
                        "name": name,
                        "offset": off,
                        "path": path,
                        "bytes": n,
                    })
                }).collect::<Vec<_>>(),
            })
        );
    } else {
        println!("setup {tag} written to {port}. complete Wi-Fi setup on the device.");
    }
    Ok(())
}

fn fetch_image(url: &str, dest: &Path, sha256: Option<&str>) -> Result<u64> {
    let sp = ui::Spinner::start("downloading firmware");
    let n = match sha256 {
        Some(h) => fwota::download_verified(url, h, dest),
        None => fwota::download(url, dest),
    };
    sp.stop();
    n
}

fn confirm(yes: bool, json: bool, prompt: &str) -> Result<()> {
    if yes || json || !io::stdin().is_terminal() {
        return Ok(());
    }
    if ask_line(prompt, false)? {
        Ok(())
    } else {
        bail!("aborted");
    }
}

/// Full-chip erase (settings, files, captures).
fn ask_erase(yes: bool, json: bool, keep_storage: bool) -> Result<bool> {
    if keep_storage {
        return Ok(false);
    }
    if yes || json || !io::stdin().is_terminal() {
        return Ok(true);
    }
    ask_line("erase all storage (settings, files, captures)?", false)
}

fn ask_line(prompt: &str, default_yes: bool) -> Result<bool> {
    let hint = if default_yes { "[Y/n]" } else { "[y/N]" };
    let line = ui::prompt_line(&format!("{prompt} {hint} "))?;
    Ok(match line.trim() {
        "" => default_yes,
        "y" | "Y" | "yes" => true,
        _ => false,
    })
}

fn pick_flash_port(explicit: Option<&str>) -> Result<String> {
    if let Some(p) = explicit {
        return Ok(p.to_string());
    }
    if let Ok(p) = infishark::serial::auto_port() {
        return Ok(p);
    }
    let ports = infishark::serial::espressif_ports()?;
    match ports.len() {
        1 => Ok(ports[0].clone()),
        0 => bail!("no Espressif USB serial port; pass --port (works on a bricked Nano)"),
        _ => bail!(
            "multiple Espressif ports ({}); pass --port",
            ports.join(", ")
        ),
    }
}

fn flash_bin(port: &str, image: &Path, offset: u32) -> Result<()> {
    flash_bins(port, &[(offset, image.to_path_buf())], false)
}

fn flash_bins(port: &str, parts: &[(u32, PathBuf)], erase_all: bool) -> Result<()> {
    let tool = find_flasher()?;
    for (offset, image) in parts {
        eprintln!(
            "flashing {} @ {offset:#x} via {}...",
            image.display(),
            tool.describe()
        );
    }
    tool.flash(port, parts, erase_all)
}

/// App-only writes go to ota_0 (0x10000). Clear otadata so the bootloader
/// does not keep booting ota_1. Skip when we already write otadata ourselves.
fn reset_otadata(erase_all: bool, parts: &[(u32, PathBuf)]) -> bool {
    !erase_all
        && parts.iter().any(|(off, _)| *off == APP_OFFSET)
        && !parts.iter().any(|(off, _)| *off == OTADATA_OFFSET)
}

enum Flasher {
    Espflash(PathBuf),
    Esptool { cmd: PathBuf, module: bool },
}

impl Flasher {
    fn describe(&self) -> String {
        match self {
            Self::Espflash(p) => p.display().to_string(),
            Self::Esptool { cmd, module: true } => format!("{} -m esptool", cmd.display()),
            Self::Esptool { cmd, .. } => cmd.display().to_string(),
        }
    }

    fn flash(&self, port: &str, parts: &[(u32, PathBuf)], erase_all: bool) -> Result<()> {
        if parts.is_empty() {
            bail!("no firmware parts to write");
        }
        match self {
            Self::Espflash(bin) => self.espflash_write(bin, port, parts, erase_all),
            Self::Esptool { cmd, module } => {
                self.esptool_write(cmd, *module, port, parts, erase_all)
            }
        }
    }

    fn espflash_write(
        &self,
        bin: &Path,
        port: &str,
        parts: &[(u32, PathBuf)],
        erase_all: bool,
    ) -> Result<()> {
        let reset_slot = reset_otadata(erase_all, parts);
        if erase_all {
            let status = Command::new(bin)
                .args([
                    "erase-flash",
                    "--port",
                    port,
                    "--chip",
                    "esp32c3",
                    "--non-interactive",
                    "--skip-update-check",
                    "--after",
                    "no-reset",
                ])
                .status()
                .with_context(|| format!("running {}", bin.display()))?;
            if !status.success() {
                bail!("espflash erase-flash failed ({status})");
            }
        } else if reset_slot {
            eprintln!("resetting OTA boot slot @ {OTADATA_OFFSET:#x}...");
            let status = Command::new(bin)
                .args([
                    "erase-region",
                    "--port",
                    port,
                    "--chip",
                    "esp32c3",
                    "--non-interactive",
                    "--skip-update-check",
                    "--after",
                    "no-reset",
                    &format!("{OTADATA_OFFSET:#x}"),
                    &format!("{OTADATA_SIZE:#x}"),
                ])
                .status()
                .with_context(|| format!("running {}", bin.display()))?;
            if !status.success() {
                bail!("espflash erase-region (otadata) failed ({status})");
            }
        }
        for (i, (offset, image)) in parts.iter().enumerate() {
            let last = i + 1 == parts.len();
            let before = if erase_all || reset_slot || i > 0 {
                "no-reset"
            } else {
                "default-reset"
            };
            let after = if last { "hard-reset" } else { "no-reset" };
            let status = Command::new(bin)
                .args([
                    "write-bin",
                    "--port",
                    port,
                    "--chip",
                    "esp32c3",
                    "--non-interactive",
                    "--skip-update-check",
                    "--before",
                    before,
                    "--after",
                    after,
                    &format!("{offset:#x}"),
                ])
                .arg(image)
                .status()
                .with_context(|| format!("running {}", bin.display()))?;
            if !status.success() {
                bail!("espflash write-bin failed ({status})");
            }
        }
        Ok(())
    }

    fn esptool_write(
        &self,
        cmd: &Path,
        module: bool,
        port: &str,
        parts: &[(u32, PathBuf)],
        erase_all: bool,
    ) -> Result<()> {
        let mut prefix: Vec<String> = if module {
            vec![cmd.display().to_string(), "-m".into(), "esptool".into()]
        } else {
            vec![cmd.display().to_string()]
        };
        prefix.extend([
            "--chip".into(),
            "esp32c3".into(),
            "--port".into(),
            port.into(),
            "--baud".into(),
            "921600".into(),
            "--before".into(),
            "default_reset".into(),
            "--after".into(),
            "hard_reset".into(),
        ]);
        if reset_otadata(erase_all, parts) {
            let mut c = Command::new(&prefix[0]);
            c.args(&prefix[1..]);
            c.args([
                "erase_region",
                &format!("{OTADATA_OFFSET:#x}"),
                &format!("{OTADATA_SIZE:#x}"),
            ]);
            let status = c.status().context("running esptool erase_region")?;
            if !status.success() {
                bail!("esptool erase_region (otadata) failed ({status})");
            }
        }
        let mut c = Command::new(&prefix[0]);
        c.args(&prefix[1..]);
        c.arg("write_flash");
        if erase_all {
            c.arg("--erase-all");
        }
        for (offset, image) in parts {
            c.arg(format!("{offset:#x}"));
            c.arg(image);
        }
        let status = c.status().context("running esptool")?;
        if !status.success() {
            bail!("esptool failed ({status})");
        }
        Ok(())
    }
}

const ESPFLASH_RELEASE: &str = "https://github.com/esp-rs/espflash/releases/download/v4.6.0";

const MISSING_FLASHER: &str = "\
need espflash or esptool to write firmware over USB.\n\
install one of:\n\
  cargo install espflash\n\
  pip install esptool";

struct EspflashAsset {
    archive: &'static str,
    sha256: &'static str,
}

/// Host builds we ship. x86_64 Linux uses the musl binary so an older glibc still runs it.
fn espflash_asset(os: &str, arch: &str) -> Option<EspflashAsset> {
    let (archive, sha256) = match (os, arch) {
        ("linux", "x86_64") => (
            "espflash-x86_64-unknown-linux-musl.zip",
            "d515ee13ae44ba913c31a2ca58dc5fd72d3362994ee1d7487a16b289dfbb6e4a",
        ),
        ("linux", "aarch64") => (
            "espflash-aarch64-unknown-linux-gnu.zip",
            "560c690ce28c7fe2b31709eeaf1fcc6717cfa832798b68287dddca1e3a3b65d6",
        ),
        ("linux", "arm") => (
            "espflash-armv7-unknown-linux-gnueabihf.zip",
            "7a6fa2890db206cd6495823ba2218b1ae55fd0f7dcafc1f8783427afcd9cdcc0",
        ),
        ("macos", "x86_64") => (
            "espflash-x86_64-apple-darwin.zip",
            "e945685fe62e45a120487b79ccecc5ac3586bbf5f4e7d78f95cc09e2227bf32d",
        ),
        ("macos", "aarch64") => (
            "espflash-aarch64-apple-darwin.zip",
            "f39bff252a181a6e345991f603d7606cf9762550e557073c1282eada46d8c757",
        ),
        ("windows", "x86_64") => (
            "espflash-x86_64-pc-windows-msvc.zip",
            "b2cb4656b067716fe2b3794cf0604b461b2476d06dee7f481704cb6c8495b11c",
        ),
        _ => return None,
    };
    Some(EspflashAsset { archive, sha256 })
}

fn espflash_bin_name() -> &'static str {
    if cfg!(windows) {
        "espflash.exe"
    } else {
        "espflash"
    }
}

fn find_flasher() -> Result<Flasher> {
    if let Some(found) = locate_flasher() {
        return Ok(found);
    }
    let Some(asset) = espflash_asset(std::env::consts::OS, std::env::consts::ARCH) else {
        bail!("{MISSING_FLASHER}");
    };
    match fetch_espflash(&asset) {
        Ok(path) => Ok(Flasher::Espflash(path)),
        Err(e) => bail!("{e:#}\n{MISSING_FLASHER}"),
    }
}

fn locate_flasher() -> Option<Flasher> {
    if let Some(p) = std::env::var_os("INFISHARK_ESPTOOL").map(PathBuf::from) {
        return Some(classify(p));
    }
    for name in ["espflash", "esptool.py", "esptool"] {
        if let Some(p) = look_in_path(name) {
            return Some(classify(p));
        }
        let t = privs::tool_path(name);
        if t.exists() {
            return Some(classify(t));
        }
    }
    for py in ["python3", "python"] {
        let t = look_in_path(py).unwrap_or_else(|| privs::tool_path(py));
        let ok = Command::new(&t)
            .args(["-m", "esptool", "version"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if ok {
            return Some(Flasher::Esptool {
                cmd: t,
                module: true,
            });
        }
    }
    if let Ok(dir) = infishark::paths::infishark_dir() {
        let installed = dir.join("tools").join(espflash_bin_name());
        if installed.is_file() {
            return Some(Flasher::Espflash(installed));
        }
    }
    None
}

fn fetch_espflash(asset: &EspflashAsset) -> Result<PathBuf> {
    let dir = infishark::paths::infishark_dir()
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .join("tools");
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let dest = dir.join(espflash_bin_name());
    if dest.is_file() {
        return Ok(dest);
    }
    eprintln!("espflash not found; installing it...");
    let zip_path = dir.join(format!("{}.download", asset.archive));
    let staged = dir.join(format!("{}.new", espflash_bin_name()));
    let url = format!("{ESPFLASH_RELEASE}/{}", asset.archive);
    fwota::download(&url, &zip_path).context("downloading espflash")?;
    let result = (|| {
        verify_sha256(&zip_path, asset.sha256)?;
        extract_espflash(&zip_path, &staged)?;
        let output = Command::new(&staged)
            .arg("--version")
            .output()
            .context("running downloaded espflash")?;
        if !output.status.success() {
            bail!("downloaded espflash --version failed ({})", output.status);
        }
        std::fs::rename(&staged, &dest).context("installing espflash")?;
        Ok(dest)
    })();
    let _ = std::fs::remove_file(&zip_path);
    if result.is_err() {
        let _ = std::fs::remove_file(&staged);
    }
    result
}

fn verify_sha256(path: &Path, expected: &str) -> Result<()> {
    let mut file = std::fs::File::open(path).context("opening espflash download")?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = file.read(&mut buf).context("reading espflash download")?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let got = hex::encode_lower(&hasher.finalize());
    if got != expected {
        bail!("espflash download SHA-256 mismatch (got {got})");
    }
    Ok(())
}

fn extract_espflash(zip_path: &Path, dest: &Path) -> Result<()> {
    let file = std::fs::File::open(zip_path).context("opening espflash archive")?;
    let mut archive = zip::ZipArchive::new(file).context("reading espflash archive")?;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).context("reading espflash archive")?;
        if !entry.is_file() {
            continue;
        }
        let name = entry.name().replace('\\', "/");
        if name != "espflash" && name != "espflash.exe" {
            continue;
        }
        let mut out =
            std::fs::File::create(dest).with_context(|| format!("create {}", dest.display()))?;
        std::io::copy(&mut entry, &mut out).context("extracting espflash")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dest, std::fs::Permissions::from_mode(0o755))?;
        }
        return Ok(());
    }
    bail!("espflash archive did not contain the espflash binary")
}

fn classify(p: PathBuf) -> Flasher {
    let name = p
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if name.contains("espflash") {
        Flasher::Espflash(p)
    } else {
        Flasher::Esptool {
            cmd: p,
            module: false,
        }
    }
}

fn look_in_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let cand = dir.join(name);
        if cand.is_file() {
            return Some(cand);
        }
        #[cfg(windows)]
        {
            let exe = dir.join(format!("{name}.exe"));
            if exe.is_file() {
                return Some(exe);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_layout_matches_web_flasher() {
        let parts = setup_parts("v0.4");
        let offs: Vec<u32> = parts.iter().map(|p| p.offset).collect();
        assert_eq!(offs, vec![0, 32_768, 57_344, 65_536]);
        assert_eq!(
            parts[0].url,
            "https://cdn.infishark.com/nano-setup-bootloader.bin"
        );
        assert_eq!(
            parts[1].url,
            "https://cdn.infishark.com/nano-setup-partitions.bin"
        );
        assert_eq!(
            parts[2].url,
            "https://cdn.infishark.com/nano-setup-bootapp.bin"
        );
        assert_eq!(
            parts[3].url,
            "https://cdn.infishark.com/v0.4-nano-setup.bin"
        );
        let v3 = setup_parts("v0.3");
        assert_eq!(v3[3].url, "https://cdn.infishark.com/v0.3-nano-setup.bin");
        assert_eq!(v3[0].url, parts[0].url);
    }

    #[test]
    fn espflash_assets_cover_release_hosts() {
        for (os, arch) in [
            ("linux", "x86_64"),
            ("linux", "aarch64"),
            ("linux", "arm"),
            ("macos", "x86_64"),
            ("macos", "aarch64"),
            ("windows", "x86_64"),
        ] {
            let asset = espflash_asset(os, arch).expect(os);
            assert!(asset.archive.ends_with(".zip"), "{}", asset.archive);
            assert_eq!(asset.sha256.len(), 64, "{os}-{arch}");
            assert!(
                asset.sha256.chars().all(|c| c.is_ascii_hexdigit()),
                "{os}-{arch}"
            );
        }
        assert!(espflash_asset("linux", "riscv64").is_none());
        assert!(
            espflash_asset("linux", "x86_64")
                .unwrap()
                .archive
                .contains("musl")
        );
    }

    #[test]
    fn app_flash_resets_otadata_unless_writing_otadata() {
        let app = PathBuf::from("app.bin");
        let ota = PathBuf::from("otadata.bin");
        assert!(reset_otadata(false, &[(APP_OFFSET, app.clone())]));
        assert!(!reset_otadata(true, &[(APP_OFFSET, app.clone())]));
        assert!(!reset_otadata(
            false,
            &[(OTADATA_OFFSET, ota), (APP_OFFSET, app)]
        ));
    }
}
