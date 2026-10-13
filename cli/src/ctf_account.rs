//! Endpoint-bound tokens: never printed; terminal-only secrets, private Unix
//! files, Windows DPAPI.
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail, ensure};
use clap::Subcommand;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::ctf_http::{MAX_RESPONSE, USER_AGENT as UA};
use crate::{ctf, ctf_http, ui};
const MAX_STORE: u64 = 16 * 1024;
const STARTUP_DEADLINE: Duration = Duration::from_millis(1500);

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Email a verification code; no password is set until verification.
    Register { email: String, username: String },
    /// Enter the emailed code visibly, then choose a password (passwords
    /// hidden).
    Verify,
    /// Request a replacement verification code.
    Resend { email: String },
    /// Log in and securely save a 30-day per-user token.
    Login { email: String },
    /// Revoke this token (or all tokens), then remove the local credential.
    Logout {
        #[arg(long, conflicts_with = "local")]
        all: bool,
        /// Forget only the local credential; does not revoke it on the server.
        #[arg(long)]
        local: bool,
    },
    /// Show the server-confirmed account, never the stored token.
    Status,
    /// List active token IDs; bearer secrets cannot be retrieved.
    Tokens,
    /// Revoke one of your tokens by ID.
    Revoke { id: String },
    /// Email a password-reset code.
    ForgotPassword { email: String },
    /// Set a new password using an emailed code; revokes every existing token.
    ResetPassword,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Account {
    pub id: String,
    pub email: String,
    pub username: String,
    pub created_at: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Login {
    token: String,
    token_type: String,
    expires_at: i64,
    #[serde(deserialize_with = "ctf::deserialize_object")]
    account: Account,
}
// Deliberately no Debug: neither JSON output nor diagnostics expose bearer
// secrets.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Credential {
    version: u32,
    endpoint: String,
    token: String,
    expires_at: i64,
    #[serde(deserialize_with = "ctf::deserialize_object")]
    account: Account,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Accepted {
    ok: bool,
    message: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OkBody {
    ok: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reset {
    ok: bool,
    account_id: String,
    login_required: bool,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Token {
    id: String,
    name: String,
    created_at: i64,
    expires_at: i64,
    current: bool,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Progress {
    slug: String,
    title: String,
    difficulty: String,
    status: String,
    created_at: Option<i64>,
    solved_at: Option<i64>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Stats {
    #[serde(deserialize_with = "ctf::deserialize_object")]
    account: Account,
    total: usize,
    issued: usize,
    solved: usize,
    challenges: Vec<ctf::JsonObject<Progress>>,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
fn shaped(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|s| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
fn validate_account(account: &Account) -> Result<()> {
    ensure!(
        shaped(&account.id, "acct_")
            && account.created_at > 0
            && (3..=24).contains(&account.username.len())
            && account
                .username
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            && account.email.len() <= 254
            && account.email.is_ascii()
            && account.email.contains('@')
            && !account.email.chars().any(char::is_control),
        "invalid account response"
    );
    Ok(())
}

pub(crate) fn normalize_endpoint(raw: &str) -> Result<String> {
    let url = Url::parse(raw.trim()).context("invalid CTF API URL")?;
    let loopback = matches!(url.host(), Some(url::Host::Ipv4(ip)) if ip.is_loopback())
        || matches!(url.host(), Some(url::Host::Ipv6(ip)) if ip.is_loopback());
    ensure!(
        (url.scheme() == "https" || url.scheme() == "http" && loopback)
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "CTF API requires HTTPS (HTTP is allowed only on literal loopback), without URL credentials, query or fragment"
    );
    Ok(url.as_str().trim_end_matches('/').to_string())
}
fn endpoint(explicit: Option<&str>) -> Result<String> {
    let raw = ctf::pick(
        explicit.map(str::to_owned),
        &["INFISHARK_CTF_URL", "CTF_URL"],
    )
    .unwrap_or_else(|| ctf::DEFAULT_URL.into());
    normalize_endpoint(&raw)
}

struct Store {
    directory: PathBuf,
}
impl Store {
    fn locate() -> Result<Self> {
        #[cfg(windows)]
        let base = std::env::var_os("APPDATA").map(PathBuf::from);
        #[cfg(not(windows))]
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|s| PathBuf::from(s).join(".config")));
        let base = base.context("cannot find account config directory")?;
        ensure!(
            base.is_absolute(),
            "account config directory must be absolute"
        );
        Ok(Self {
            directory: base.join("infishark").join("ctf"),
        })
    }
    fn path(&self) -> PathBuf {
        self.directory.join("account.json")
    }
    fn check_directory(&self) -> Result<bool> {
        match fs::symlink_metadata(&self.directory) {
            Ok(meta) => {
                check_private(&meta, true)?;
                Ok(true)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e).context("inspect account directory"),
        }
    }
    fn load(&self) -> Result<Option<Credential>> {
        if !self.check_directory()? {
            return Ok(None);
        }
        let path = self.path();
        match fs::symlink_metadata(&path) {
            Ok(meta) => check_private(&meta, false)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).context("inspect account credential"),
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let file = options.open(path).context("open account credential")?;
        check_private(&file.metadata()?, false)?;
        let mut bytes = Vec::new();
        file.take(MAX_STORE + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= MAX_STORE,
            "account credential is too large"
        );
        let bytes = unprotect(bytes)?;
        let ctf::JsonObject(credential) =
            serde_json::from_slice::<ctf::JsonObject<Credential>>(&bytes).map_err(|_| {
                anyhow::anyhow!("invalid stored account credential; use ctf account logout --local")
            })?;
        ensure!(
            credential.version == 1
                && shaped(&credential.token, "ctf_")
                && credential.expires_at > 0
                && normalize_endpoint(&credential.endpoint)? == credential.endpoint,
            "invalid stored account credential"
        );
        validate_account(&credential.account)?;
        Ok(Some(credential))
    }
    fn save(&self, credential: &Credential) -> Result<()> {
        if !self.check_directory()? {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder
                .create(&self.directory)
                .context("create private account directory")?;
        }
        self.check_directory()?;
        if let Ok(meta) = fs::symlink_metadata(self.path()) {
            check_private(&meta, false)?;
        }
        let data = protect(serde_json::to_vec(credential)?)?;
        let mut random = [0; 16];
        rand::rngs::OsRng.fill_bytes(&mut random);
        let temporary = self.directory.join(format!(
            ".account-{}.tmp",
            infishark::hex::encode_lower(&random)
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let mut file = options
            .open(&temporary)
            .context("create private credential file")?;
        let result = (|| -> Result<()> {
            file.write_all(&data)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temporary, self.path()).context("save account credential")?;
            Ok(())
        })();
        // Only this call's create_new temporary file is ever cleaned up.
        if temporary.exists() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
    fn clear(&self) -> Result<()> {
        if !self.check_directory()? {
            return Ok(());
        }
        let path = self.path();
        match fs::symlink_metadata(&path) {
            Ok(meta) => {
                check_private(&meta, false)?;
                fs::remove_file(path).context("remove account credential")
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).context("inspect account credential"),
        }
    }
}
fn check_private(meta: &fs::Metadata, directory: bool) -> Result<()> {
    ensure!(
        !meta.file_type().is_symlink()
            && if directory {
                meta.is_dir()
            } else {
                meta.is_file()
            },
        "unsafe account credential path (symlink or wrong file type)"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        ensure!(
            meta.uid() == unsafe { libc::geteuid() } && meta.permissions().mode() & 0o077 == 0,
            "account storage must be owned by you and private (directory 0700, file 0600)"
        );
    }
    Ok(())
}
#[cfg(unix)]
fn protect(bytes: Vec<u8>) -> Result<Vec<u8>> {
    Ok(bytes)
}
#[cfg(unix)]
fn unprotect(bytes: Vec<u8>) -> Result<Vec<u8>> {
    Ok(bytes)
}
#[cfg(windows)]
fn protect(bytes: Vec<u8>) -> Result<Vec<u8>> {
    dpapi(bytes, true)
}
#[cfg(windows)]
fn unprotect(bytes: Vec<u8>) -> Result<Vec<u8>> {
    dpapi(bytes, false)
}
#[cfg(windows)]
fn dpapi(mut bytes: Vec<u8>, encrypt: bool) -> Result<Vec<u8>> {
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    };
    let input = CRYPT_INTEGER_BLOB {
        cbData: bytes.len().try_into()?,
        pbData: bytes.as_mut_ptr(),
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    // User-scoped DPAPI, never CRYPTPROTECT_LOCAL_MACHINE or interactive OS
    // prompts.
    let ok = unsafe {
        if encrypt {
            CryptProtectData(
                &input,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        }
    };
    ensure!(ok != 0, "Windows account credential protection failed");
    let result =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        windows_sys::Win32::Foundation::LocalFree(output.pbData.cast());
    }
    Ok(result)
}
#[cfg(not(any(unix, windows)))]
fn protect(_: Vec<u8>) -> Result<Vec<u8>> {
    bail!("secure account storage is unsupported on this platform")
}
#[cfg(not(any(unix, windows)))]
fn unprotect(_: Vec<u8>) -> Result<Vec<u8>> {
    bail!("secure account storage is unsupported on this platform")
}

#[derive(Clone, Debug, PartialEq)]
enum StartupStatus {
    NotSignedIn,
    Checking(String),
    SignedIn(String),
    SignInRequired,
    Unverified(String),
    Unavailable,
}
impl StartupStatus {
    fn message(&self) -> String {
        match self {
            Self::NotSignedIn => "CTF: not signed in".into(),
            Self::Checking(username) => {
                format!("CTF: saved account {username}; checking session")
            }
            Self::SignedIn(username) => format!("CTF: signed in as {username}"),
            Self::SignInRequired => "CTF: sign-in required".into(),
            Self::Unverified(username) => {
                format!("CTF: saved account {username}; couldn't verify session")
            }
            Self::Unavailable => "CTF: couldn't read account status".into(),
        }
    }
}

pub struct StartupCheck {
    status: StartupStatus,
    pending: Option<(std::sync::mpsc::Receiver<StartupStatus>, StartupStatus)>,
}

impl StartupCheck {
    fn complete(status: StartupStatus) -> Self {
        Self {
            status,
            pending: None,
        }
    }

    pub fn message(&self) -> String {
        self.status.message()
    }

    pub fn is_pending(&self) -> bool {
        self.pending.is_some()
    }

    /// Called only by the shell, while it owns terminal output.
    pub fn poll_update(&mut self) -> Option<String> {
        use std::sync::mpsc::TryRecvError;
        let (rx, fallback) = self.pending.as_ref()?;
        let status = match rx.try_recv() {
            Ok(status) => status,
            Err(TryRecvError::Empty) => return None,
            Err(TryRecvError::Disconnected) => fallback.clone(),
        };
        self.status = status;
        self.pending = None;
        Some(self.message())
    }
}

pub fn startup_status() -> StartupCheck {
    match Store::locate() {
        Ok(store) => begin_startup_status_for(&store, endpoint(None), STARTUP_DEADLINE),
        Err(_) => StartupCheck::complete(StartupStatus::Unavailable),
    }
}

fn begin_startup_status_for(
    store: &Store,
    endpoint: Result<String>,
    deadline: Duration,
) -> StartupCheck {
    let profile = match store.load() {
        Ok(Some(profile)) => profile,
        Ok(None) => return StartupCheck::complete(StartupStatus::NotSignedIn),
        Err(_) => return StartupCheck::complete(StartupStatus::Unavailable),
    };
    let unverified = StartupStatus::Unverified(profile.account.username.clone());
    if endpoint
        .as_ref()
        .map_or(true, |base| base != &profile.endpoint)
    {
        // Never send the credential to an overridden API.
        return StartupCheck::complete(unverified);
    }
    if profile.expires_at <= now() {
        return StartupCheck::complete(StartupStatus::SignInRequired);
    }
    begin_startup_probe(profile.account.username.clone(), deadline, move || {
        probe_session(profile, deadline)
    })
}

fn begin_startup_probe(
    username: String,
    deadline: Duration,
    probe: impl FnOnce() -> StartupStatus + Send + 'static,
) -> StartupCheck {
    let fallback = StartupStatus::Unverified(username.clone());
    let worker_fallback = fallback.clone();
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    // The shell never waits for networking, including DNS. A second, bounded
    // worker wait still reports an unverified session if DNS stalls.
    if std::thread::Builder::new()
        .name("ctf-account-startup".into())
        .spawn(move || {
            let status = with_startup_deadline(deadline, worker_fallback, probe);
            let _ = tx.try_send(status);
        })
        .is_err()
    {
        return StartupCheck::complete(fallback);
    }
    StartupCheck {
        status: StartupStatus::Checking(username),
        pending: Some((rx, fallback)),
    }
}

#[cfg(test)]
fn startup_status_for(
    store: &Store,
    endpoint: Result<String>,
    deadline: Duration,
) -> StartupStatus {
    let check = begin_startup_status_for(store, endpoint, deadline);
    match check.pending {
        Some((rx, fallback)) => rx
            .recv_timeout(deadline + Duration::from_millis(250))
            .unwrap_or(fallback),
        None => check.status,
    }
}

fn with_startup_deadline(
    deadline: Duration,
    fallback: StartupStatus,
    probe: impl FnOnce() -> StartupStatus + Send + 'static,
) -> StartupStatus {
    let started = std::time::Instant::now();
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    if std::thread::Builder::new()
        .name("ctf-account-status".into())
        .spawn(move || {
            let _ = tx.send(probe());
        })
        .is_err()
    {
        return fallback;
    }
    rx.recv_timeout(deadline.saturating_sub(started.elapsed()))
        .unwrap_or(fallback)
}

fn probe_session(profile: Credential, deadline: Duration) -> StartupStatus {
    let fallback = StartupStatus::Unverified(profile.account.username.clone());
    let agent = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout_connect(deadline)
        .timeout(deadline)
        .build();
    let response = match agent
        .get(&format!("{}/v1/account", profile.endpoint))
        .set("User-Agent", UA)
        .set("Authorization", &format!("Bearer {}", profile.token))
        .call()
    {
        Ok(response) if response.status() == 200 => response,
        Err(ureq::Error::Status(401, _)) => return StartupStatus::SignInRequired,
        _ => return fallback,
    };
    let mut bytes = Vec::new();
    if response
        .into_reader()
        .take(MAX_RESPONSE + 1)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() as u64 > MAX_RESPONSE
    {
        return fallback;
    }
    match serde_json::from_slice::<ctf::JsonObject<Account>>(&bytes) {
        Ok(ctf::JsonObject(account))
            if validate_account(&account).is_ok() && account.id == profile.account.id =>
        {
            StartupStatus::SignedIn(account.username)
        }
        _ => fallback,
    }
}

fn bound<'a>(credential: &'a Credential, endpoint: &str) -> Result<&'a Credential> {
    ensure!(
        credential.endpoint == endpoint,
        "stored account belongs to a different CTF API; log in explicitly at this URL"
    );
    Ok(credential)
}
pub(crate) fn credential(endpoint: &str, explicit: Option<String>) -> Result<String> {
    // Explicit overrides are intentional; stored tokens never follow a URL
    // override.
    if let Some(token) = explicit {
        return Ok(token);
    }
    let profile = Store::locate()?.load()?.context(
        "log in first with infishark ctf account login <email> (or supply a per-user token)",
    )?;
    let profile = bound(&profile, endpoint)?;
    ensure!(
        profile.expires_at > now(),
        "stored CTF token expired; run infishark ctf account login <email>"
    );
    Ok(profile.token.clone())
}
fn rpc<T: serde::de::DeserializeOwned>(
    endpoint: &str,
    path: &str,
    token: Option<&str>,
    body: Option<serde_json::Value>,
    expected: u16,
) -> Result<T> {
    let agent = ctf_http::agent();
    let url = format!("{endpoint}{path}");
    let mut request = agent
        .request(if body.is_some() { "POST" } else { "GET" }, &url)
        .set("User-Agent", UA);
    if let Some(token) = token {
        request = request.set("Authorization", &format!("Bearer {token}"));
    }
    let response = ctf_http::request(request, body.as_ref())?;
    if response.status() >= 400 {
        bail!("{}", status_error(response.status()));
    }
    ensure!(
        response.status() == expected,
        "unexpected CTF account HTTP {}",
        response.status()
    );
    let bytes = ctf_http::read_body(response, MAX_RESPONSE)?;
    serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("invalid CTF account response"))
}
fn status_error(status: u16) -> String {
    let reason = match status {
        400 => "invalid input, common/blocked password or expired email code",
        401 => "invalid/expired credentials; log in again",
        409 => "account name conflict or active token limit; choose another name or revoke a token",
        429 => "rate limited; try again later",
        503 => "email delivery is unavailable",
        _ => "request rejected",
    };
    format!("CTF account HTTP {status}: {reason}")
}
fn object<T: serde::de::DeserializeOwned>(
    endpoint: &str,
    path: &str,
    token: Option<&str>,
    body: Option<serde_json::Value>,
    expected: u16,
) -> Result<T> {
    let ctf::JsonObject(value) = rpc(endpoint, path, token, body, expected)?;
    Ok(value)
}
fn password_valid(password: &str) -> bool {
    password.len() <= 512
        && (12..=128).contains(&password.chars().count())
        && !password.contains('\0')
}
fn new_password() -> Result<String> {
    let password = ui::prompt_secret("New password (12-128 characters): ")?;
    ensure!(
        password_valid(&password),
        "password must be 12-128 characters, without NUL"
    );
    ensure!(
        password == ui::prompt_secret("Confirm password: ")?,
        "passwords do not match"
    );
    Ok(password)
}
fn output<T: Serialize>(value: &T, json: bool, message: &str) -> Result<()> {
    crate::print_action(serde_json::to_value(value)?, message, json)
}
fn sign_in(store: &Store, endpoint: &str, email: &str, password: String) -> Result<Account> {
    let login: Login = object(
        endpoint,
        "/v1/account/login",
        None,
        Some(serde_json::json!({"email":email,"password":password})),
        200,
    )?;
    validate_account(&login.account)?;
    ensure!(
        login.token_type == "Bearer" && shaped(&login.token, "ctf_") && login.expires_at > now(),
        "invalid account login response"
    );
    let profile = Credential {
        version: 1,
        endpoint: endpoint.into(),
        token: login.token,
        expires_at: login.expires_at,
        account: login.account,
    };
    if let Err(error) = store.save(&profile) {
        // Avoid stranding a newly minted token when protected local storage fails.
        let _: Result<OkBody> = object(
            endpoint,
            "/v1/account/logout",
            Some(&profile.token),
            Some(serde_json::json!({})),
            200,
        );
        return Err(error);
    }
    Ok(profile.account)
}

pub fn run(command: &Command, explicit_url: Option<&str>, json: bool) -> Result<()> {
    let endpoint = endpoint(explicit_url)?;
    match command {
        Command::Register { email, username } => {
            let accepted: Accepted = object(
                &endpoint,
                "/v1/account/register",
                None,
                Some(serde_json::json!({"email":email,"username":username})),
                202,
            )?;
            ensure!(accepted.ok, "registration was not accepted");
            output(
                &serde_json::json!({"ok":true}),
                json,
                "If eligible, a code was emailed. Run infishark ctf account verify.",
            )
        }
        Command::Resend { email } | Command::ForgotPassword { email } => {
            let path = if matches!(command, Command::Resend { .. }) {
                "/v1/account/resend"
            } else {
                "/v1/account/password/forgot"
            };
            let accepted: Accepted = object(
                &endpoint,
                path,
                None,
                Some(serde_json::json!({"email":email})),
                202,
            )?;
            ensure!(accepted.ok, "email request was not accepted");
            output(
                &serde_json::json!({"ok":true}),
                json,
                "If eligible, a replacement code was emailed.",
            )
        }
        Command::Verify => {
            let token = ui::prompt_code("Verification code: ", ui::CodeEcho::Visible)?;
            ensure!(shaped(&token, "ctfv_"), "invalid verification code");
            let password = new_password()?;
            let account: Account = object(
                &endpoint,
                "/v1/account/verify",
                None,
                Some(serde_json::json!({"token":token,"password":password})),
                201,
            )?;
            validate_account(&account)?;
            output(
                &account,
                json,
                "Account verified. Run infishark ctf account login <email>.",
            )
        }
        Command::Login { email } => {
            let store = Store::locate()?;
            let account = sign_in(&store, &endpoint, email, ui::prompt_secret("Password: ")?)?;
            output(
                &account,
                json,
                &format!(
                    "Logged in as {}. Token saved securely for {endpoint}.",
                    account.username
                ),
            )
        }
        Command::ResetPassword => {
            let token = ui::prompt_code("Password-reset code: ", ui::CodeEcho::Masked)?;
            ensure!(shaped(&token, "ctfr_"), "invalid password-reset code");
            let password = new_password()?;
            let result: Reset = object(
                &endpoint,
                "/v1/account/password/reset",
                None,
                Some(serde_json::json!({"token":token,"password":password})),
                200,
            )?;
            ensure!(
                result.ok && result.login_required && shaped(&result.account_id, "acct_"),
                "invalid password-reset response"
            );
            let store = Store::locate()?;
            if let Some(profile) = store.load()? {
                if profile.endpoint == endpoint && profile.account.id == result.account_id {
                    store.clear()?;
                }
            }
            output(
                &serde_json::json!({"ok":true,"login_required":true}),
                json,
                "Password changed; all old tokens revoked. Log in again.",
            )
        }
        Command::Logout { all, local } => {
            let store = Store::locate()?;
            if *local {
                store.clear()?;
                return output(
                    &serde_json::json!({"ok":true,"local_only":true}),
                    json,
                    "Local credential removed. Server token was NOT revoked.",
                );
            }
            let profile = store
                .load()?
                .context("no saved CTF account; use logout --local to clear a local credential")?;
            bound(&profile, &endpoint)?;
            let path = if *all {
                "/v1/account/logout-all"
            } else {
                "/v1/account/logout"
            };
            let result: OkBody = object(
                &endpoint,
                path,
                Some(&profile.token),
                Some(serde_json::json!({})),
                200,
            )?;
            ensure!(
                result.ok,
                "token revocation was not confirmed; local credential retained"
            );
            store.clear()?;
            output(&result, json, "Token revoked and local credential removed.")
        }
        Command::Status => {
            let token = credential(&endpoint, None)?;
            let account: Account = object(&endpoint, "/v1/account", Some(&token), None, 200)?;
            validate_account(&account)?;
            output(
                &account,
                json,
                &format!("{} <{}> on {endpoint}", account.username, account.email),
            )
        }
        Command::Tokens => {
            let token = credential(&endpoint, None)?;
            let tokens: Vec<ctf::JsonObject<Token>> =
                rpc(&endpoint, "/v1/account/tokens", Some(&token), None, 200)?;
            ensure!(
                tokens.len() <= 20
                    && tokens
                        .iter()
                        .all(|t| shaped(&t.0.id, "tok_") && t.0.expires_at > now()),
                "invalid token-list response"
            );
            if json {
                println!("{}", serde_json::to_string(&tokens)?);
            } else {
                let rows = tokens
                    .into_iter()
                    .map(|ctf::JsonObject(t)| {
                        vec![
                            t.id,
                            t.name,
                            t.expires_at.to_string(),
                            if t.current {
                                "yes".into()
                            } else {
                                String::new()
                            },
                        ]
                    })
                    .collect::<Vec<_>>();
                ui::text_table(&["TOKEN ID", "NAME", "EXPIRES (UNIX)", "CURRENT"], &rows);
            }
            Ok(())
        }
        Command::Revoke { id } => {
            ensure!(shaped(id, "tok_"), "invalid token ID");
            let token = credential(&endpoint, None)?;
            let result: OkBody = object(
                &endpoint,
                &format!("/v1/account/tokens/{id}/revoke"),
                Some(&token),
                Some(serde_json::json!({})),
                200,
            )?;
            ensure!(result.ok, "token revocation was not confirmed");
            output(
                &result,
                json,
                "Token revoked. If this was your current token, log in again.",
            )
        }
    }
}

pub fn stats(json: bool, opts: ctf::ApiOpts) -> Result<()> {
    let endpoint = endpoint(opts.url.as_deref())?;
    let explicit = ctf::pick(opts.token, &["INFISHARK_CTF_TOKEN", "CTF_TOKEN"]);
    let token = credential(&endpoint, explicit)?;
    let stats: Stats = object(&endpoint, "/v1/stats", Some(&token), None, 200)?;
    validate_account(&stats.account)?;
    ensure!(
        stats.total == stats.challenges.len()
            && stats.solved <= stats.issued
            && stats.issued <= stats.total
            && stats
                .challenges
                .iter()
                .all(|p| matches!(p.0.status.as_str(), "unissued" | "issued" | "solved")),
        "invalid account stats response"
    );
    if json {
        println!("{}", serde_json::to_string(&stats)?);
    } else {
        println!(
            "{}: {}/{} solved, {} issued",
            stats.account.username, stats.solved, stats.total, stats.issued
        );
        let rows = stats
            .challenges
            .into_iter()
            .map(|ctf::JsonObject(p)| vec![p.slug, p.status, p.difficulty, p.title])
            .collect::<Vec<_>>();
        ui::text_table(&["CHALLENGE", "STATUS", "DIFFICULTY", "TITLE"], &rows);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn profile() -> Credential {
        Credential {
            version: 1,
            endpoint: "https://ctf.infishark.com".into(),
            token: format!("ctf_{}", "a".repeat(64)),
            expires_at: now() + 3600,
            account: Account {
                id: format!("acct_{}", "b".repeat(64)),
                email: "alice@example.com".into(),
                username: "alice".into(),
                created_at: 1,
            },
        }
    }
    struct Temp(Store);
    impl Temp {
        fn new() -> Self {
            let mut nonce = [0; 16];
            rand::rngs::OsRng.fill_bytes(&mut nonce);
            Self(Store {
                directory: std::env::temp_dir().join(format!(
                    "infishark-account-test-{}",
                    infishark::hex::encode_lower(&nonce)
                )),
            })
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0.directory);
        }
    }
    #[test]
    fn new_password_bounds_count_unicode_scalars_without_trimming() {
        for ch in ["a", "\u{e9}", "\u{1f988}"] {
            assert!(!password_valid(&ch.repeat(11)));
            assert!(password_valid(&ch.repeat(12)));
            assert!(password_valid(&ch.repeat(128)));
            assert!(!password_valid(&ch.repeat(129)));
        }
        assert!(!password_valid(&"\u{e9}".repeat(6)));
        assert!(password_valid(&"e\u{301}".repeat(6)));
        assert!(password_valid(" soft coral breeze "));
        assert!(!password_valid("valid-password\0"));
    }

    fn status_server(
        status: u16,
        body: Vec<u8>,
        headers: &str,
        body_delay: Duration,
    ) -> (String, std::thread::JoinHandle<String>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let headers = headers.to_string();
        let worker = std::thread::spawn(move || {
            listener.set_nonblocking(true).unwrap();
            let start = std::time::Instant::now();
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            start.elapsed() < Duration::from_secs(3),
                            "status probe never connected"
                        );
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(e) => panic!("accept status probe: {e}"),
                }
            };
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            let mut byte = [0];
            while !request.ends_with(b"\r\n\r\n") {
                assert!(request.len() < 8192);
                socket.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            let head = format!(
                "HTTP/1.1 {status} test\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n",
                body.len()
            );
            let _ = socket.write_all(head.as_bytes());
            std::thread::sleep(body_delay);
            let _ = socket.write_all(&body);
            String::from_utf8(request).unwrap()
        });
        (endpoint, worker)
    }

    #[test]
    fn startup_status_skips_network_without_a_saved_matching_unexpired_session() {
        let t = Temp::new();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let check = || startup_status_for(&t.0, Ok(endpoint.clone()), Duration::from_millis(100));
        assert_eq!(check(), StartupStatus::NotSignedIn);
        let mut p = profile();
        t.0.save(&p).unwrap();
        let before = fs::read(t.0.path()).unwrap();
        assert_eq!(check(), StartupStatus::Unverified("alice".into()));
        assert_eq!(fs::read(t.0.path()).unwrap(), before);
        p.endpoint = endpoint.clone();
        p.expires_at = now() - 1;
        t.0.save(&p).unwrap();
        let before = fs::read(t.0.path()).unwrap();
        assert_eq!(check(), StartupStatus::SignInRequired);
        assert_eq!(fs::read(t.0.path()).unwrap(), before);
        p.expires_at = now() + 3600;
        t.0.save(&p).unwrap();
        assert_eq!(
            startup_status_for(
                &t.0,
                Err(anyhow::anyhow!("bad URL")),
                Duration::from_millis(100)
            ),
            StartupStatus::Unverified("alice".into())
        );
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        fs::write(t.0.path(), protect(b"[]".to_vec()).unwrap()).unwrap();
        let before = fs::read(t.0.path()).unwrap();
        assert_eq!(check(), StartupStatus::Unavailable);
        assert_eq!(fs::read(t.0.path()).unwrap(), before);
    }

    #[test]
    fn startup_status_only_trusts_a_valid_confirmed_account_and_never_changes_storage() {
        let t = Temp::new();
        let mut confirmed = serde_json::to_value(profile().account).unwrap();
        confirmed["username"] = "renamed".into();
        let mut wrong_id = confirmed.clone();
        wrong_id["id"] = format!("acct_{}", "c".repeat(64)).into();
        let mut unsafe_name = confirmed.clone();
        unsafe_name["username"] = "unsafe\u{1b}[31m".into();
        let fallback = StartupStatus::Unverified("alice".into());
        for (status, body, expected) in [
            (
                200,
                serde_json::to_vec(&confirmed).unwrap(),
                StartupStatus::SignedIn("renamed".into()),
            ),
            (
                401,
                b"secret-provider-error".to_vec(),
                StartupStatus::SignInRequired,
            ),
            (403, b"secret-provider-error".to_vec(), fallback.clone()),
            (404, Vec::new(), fallback.clone()),
            (429, Vec::new(), fallback.clone()),
            (500, Vec::new(), fallback.clone()),
            (200, b"[]".to_vec(), fallback.clone()),
            (
                200,
                b"malformed secret-provider-error".to_vec(),
                fallback.clone(),
            ),
            (
                200,
                serde_json::to_vec(&wrong_id).unwrap(),
                fallback.clone(),
            ),
            (
                200,
                serde_json::to_vec(&unsafe_name).unwrap(),
                fallback.clone(),
            ),
            (200, vec![b'x'; MAX_RESPONSE as usize + 1], fallback.clone()),
        ] {
            let (endpoint, worker) = status_server(status, body, "", Duration::ZERO);
            let mut p = profile();
            p.endpoint = endpoint.clone();
            t.0.save(&p).unwrap();
            let before = fs::read(t.0.path()).unwrap();
            let result = startup_status_for(&t.0, Ok(endpoint), Duration::from_secs(1));
            assert_eq!(result, expected);
            assert_eq!(fs::read(t.0.path()).unwrap(), before);
            let message = result.message();
            assert!(!message.contains(&p.token));
            assert!(!message.contains("secret-provider-error"));
            assert!(!message.contains("offline"));
            let request = worker.join().unwrap();
            assert!(request.starts_with("GET /v1/account HTTP/1.1\r\n"));
            assert_eq!(
                request
                    .to_ascii_lowercase()
                    .matches("authorization:")
                    .count(),
                1
            );
        }
    }

    #[test]
    fn startup_status_never_follows_redirects_or_forwards_a_token() {
        let t = Temp::new();
        let trap = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        trap.set_nonblocking(true).unwrap();
        let location = format!("Location: http://{}/trap\r\n", trap.local_addr().unwrap());
        let (endpoint, worker) = status_server(302, Vec::new(), &location, Duration::ZERO);
        let mut p = profile();
        p.endpoint = endpoint.clone();
        t.0.save(&p).unwrap();
        assert_eq!(
            startup_status_for(&t.0, Ok(endpoint), Duration::from_secs(1)),
            StartupStatus::Unverified("alice".into())
        );
        worker.join().unwrap();
        assert_eq!(
            trap.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn startup_status_connection_failure_and_slow_body_are_not_offline_or_logout() {
        let t = Temp::new();
        // Port zero cannot be a listening TCP destination; do not release an
        // ephemeral port that another parallel test could immediately reuse.
        let endpoint = "http://127.0.0.1:0".to_string();
        let mut p = profile();
        p.endpoint = endpoint.clone();
        t.0.save(&p).unwrap();
        let before = fs::read(t.0.path()).unwrap();
        assert_eq!(
            startup_status_for(&t.0, Ok(endpoint), Duration::from_millis(100)),
            StartupStatus::Unverified("alice".into())
        );
        assert_eq!(fs::read(t.0.path()).unwrap(), before);
        let (endpoint, worker) = status_server(
            200,
            serde_json::to_vec(&p.account).unwrap(),
            "",
            Duration::from_millis(350),
        );
        p.endpoint = endpoint.clone();
        t.0.save(&p).unwrap();
        let before = fs::read(t.0.path()).unwrap();
        let start = std::time::Instant::now();
        assert_eq!(
            startup_status_for(&t.0, Ok(endpoint), Duration::from_millis(30)),
            StartupStatus::Unverified("alice".into())
        );
        assert!(start.elapsed() < Duration::from_millis(300));
        worker.join().unwrap();
        assert_eq!(fs::read(t.0.path()).unwrap(), before);
    }

    #[test]
    fn startup_check_is_nonblocking_and_reports_a_stalled_probe_once() {
        let (release, waiting) = std::sync::mpsc::channel();
        let (started, probing) = std::sync::mpsc::channel();
        let (done, finished) = std::sync::mpsc::channel();
        let mut check = begin_startup_probe("alice".into(), Duration::from_millis(40), move || {
            started.send(()).unwrap();
            waiting.recv().unwrap();
            done.send(()).unwrap();
            StartupStatus::SignedIn("alice".into())
        });
        assert_eq!(check.status, StartupStatus::Checking("alice".into()));
        assert!(check.is_pending());
        assert!(!check.message().contains("signed in as"));
        probing.recv_timeout(Duration::from_secs(1)).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        let update = loop {
            if let Some(update) = check.poll_update() {
                break update;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "probe deadline did not report"
            );
            std::thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(update, StartupStatus::Unverified("alice".into()).message());
        assert!(!check.is_pending());
        release.send(()).unwrap();
        finished.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(check.poll_update(), None);
        assert_eq!(check.status, StartupStatus::Unverified("alice".into()));
    }

    #[test]
    fn failed_startup_worker_never_leaves_a_check_pending() {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        drop(tx);
        let fallback = StartupStatus::Unverified("alice".into());
        let mut check = StartupCheck {
            status: StartupStatus::Checking("alice".into()),
            pending: Some((rx, fallback.clone())),
        };
        assert_eq!(check.poll_update(), Some(fallback.message()));
        assert!(!check.is_pending());
        assert_eq!(check.poll_update(), None);
    }

    #[test]
    fn startup_wait_is_bounded_even_if_dns_or_a_worker_stalls() {
        let (release, waiting) = std::sync::mpsc::channel();
        let (done, finished) = std::sync::mpsc::channel();
        let start = std::time::Instant::now();
        let result = with_startup_deadline(
            Duration::from_millis(20),
            StartupStatus::Unverified("alice".into()),
            move || {
                waiting.recv().unwrap();
                done.send(()).unwrap();
                StartupStatus::SignedIn("alice".into())
            },
        );
        assert_eq!(result, StartupStatus::Unverified("alice".into()));
        assert!(start.elapsed() < Duration::from_millis(300));
        release.send(()).unwrap();
        finished.recv_timeout(Duration::from_secs(1)).unwrap();
    }

    #[test]
    fn endpoint_validation_is_canonical_and_fail_closed() {
        assert_eq!(
            normalize_endpoint(" HTTPS://CTF.INFISHARK.COM:443/ ").unwrap(),
            "https://ctf.infishark.com"
        );
        assert!(normalize_endpoint("http://127.0.0.1:9999").is_ok());
        assert!(normalize_endpoint("http://[::1]:9999").is_ok());
        for url in [
            "",
            "http://ctf.infishark.com",
            "http://localhost:9999",
            "https://u:p@example.com",
            "https://example.com?token=x",
            "https://example.com#x",
            "file:///tmp/server",
        ] {
            assert!(normalize_endpoint(url).is_err());
        }
    }
    #[test]
    fn stored_token_cannot_follow_another_origin_port_or_path() {
        let p = profile();
        assert!(bound(&p, &p.endpoint).is_ok());
        for endpoint in [
            "https://evil.example",
            "https://ctf.infishark.com:8443",
            "https://ctf.infishark.com/other",
            "http://127.0.0.1:9999",
        ] {
            assert!(bound(&p, endpoint).is_err());
        }
    }
    #[test]
    fn store_roundtrip_private_atomic_replacement_and_clear() {
        let t = Temp::new();
        assert!(t.0.load().unwrap().is_none());
        let mut p = profile();
        t.0.save(&p).unwrap();
        assert_eq!(t.0.load().unwrap().unwrap().token, p.token);
        p.token = format!("ctf_{}", "c".repeat(64));
        t.0.save(&p).unwrap();
        assert_eq!(t.0.load().unwrap().unwrap().token, p.token);
        assert_eq!(fs::read_dir(&t.0.directory).unwrap().count(), 1);
        t.0.clear().unwrap();
        t.0.clear().unwrap();
        assert!(t.0.load().unwrap().is_none());
    }
    #[cfg(unix)]
    #[test]
    fn refuses_symlinks_and_broad_directory_or_file_permissions() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let t = Temp::new();
        t.0.save(&profile()).unwrap();
        fs::set_permissions(t.0.path(), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(t.0.load().is_err());
        assert!(t.0.save(&profile()).is_err());
        fs::set_permissions(t.0.path(), fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&t.0.directory, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(t.0.load().is_err());
        assert!(t.0.save(&profile()).is_err());
        fs::set_permissions(&t.0.directory, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_file(t.0.path()).unwrap();
        let elsewhere = Temp::new();
        elsewhere.0.save(&profile()).unwrap();
        symlink(elsewhere.0.path(), t.0.path()).unwrap();
        assert!(t.0.load().is_err());
        assert!(t.0.save(&profile()).is_err());
        assert!(t.0.clear().is_err());
        fs::remove_file(t.0.path()).unwrap();
        fs::remove_dir(&t.0.directory).unwrap();
        symlink(&elsewhere.0.directory, &t.0.directory).unwrap();
        assert!(t.0.load().is_err());
        assert!(t.0.save(&profile()).is_err());
        fs::remove_file(&t.0.directory).unwrap();
    }
    #[test]
    fn store_rejects_duplicate_unknown_array_invalid_and_oversized_data() {
        let t = Temp::new();
        t.0.save(&profile()).unwrap();
        for data in [
            b"[]".to_vec(),
            b"{\"version\":1,\"version\":1}".to_vec(),
            vec![b'x'; MAX_STORE as usize + 1],
        ] {
            fs::write(t.0.path(), protect(data).unwrap()).unwrap();
            assert!(t.0.load().is_err());
        }
        let mut value = serde_json::to_value(profile()).unwrap();
        value["extra"] = true.into();
        fs::write(
            t.0.path(),
            protect(serde_json::to_vec(&value).unwrap()).unwrap(),
        )
        .unwrap();
        assert!(t.0.load().is_err());
        let mut p = profile();
        p.token = "ctfv_wrong-purpose".into();
        t.0.save(&p).unwrap();
        assert!(t.0.load().is_err());
    }
    #[test]
    fn account_cli_parses_without_hardware_and_rejects_secrets_in_argv() {
        use clap::Parser;
        for args in [
            vec!["infishark", "ctf", "account", "login", "alice@example.test"],
            vec![
                "infishark",
                "ctf",
                "account",
                "verify",
                "--url",
                "http://127.0.0.1:9999",
            ],
            vec!["infishark", "ctf", "account", "logout", "--local"],
            vec!["infishark", "ctf", "stats"],
        ] {
            assert!(crate::Cli::try_parse_from(args).is_ok());
        }
        for args in [
            vec![
                "infishark",
                "ctf",
                "account",
                "login",
                "alice@example.test",
                "--password",
                "unsafe",
            ],
            vec!["infishark", "ctf", "account", "verify", "--code", "unsafe"],
            vec!["infishark", "ctf", "account", "logout", "--local", "--all"],
        ] {
            assert!(crate::Cli::try_parse_from(args).is_err());
        }
    }
    #[test]
    fn login_schema_rejects_array_duplicate_unknown_and_nested_array_fields() {
        let p = profile();
        let value = serde_json::json!({"token":p.token,"token_type":"Bearer","expires_at":p.expires_at,"account":p.account});
        let valid = value.to_string();
        assert!(serde_json::from_str::<ctf::JsonObject<Login>>(&valid).is_ok());
        assert!(serde_json::from_str::<ctf::JsonObject<Login>>("[]").is_err());
        let duplicate = valid.replacen(
            "\"token_type\":\"Bearer\"",
            "\"token_type\":\"Bearer\",\"token_type\":\"Bearer\"",
            1,
        );
        assert!(serde_json::from_str::<ctf::JsonObject<Login>>(&duplicate).is_err());
        let mut bad = value.clone();
        bad["extra"] = true.into();
        assert!(serde_json::from_str::<ctf::JsonObject<Login>>(&bad.to_string()).is_err());
        let mut bad = value;
        bad["account"] = serde_json::json!([
            p.account.id,
            p.account.email,
            p.account.username,
            p.account.created_at
        ]);
        assert!(serde_json::from_str::<ctf::JsonObject<Login>>(&bad.to_string()).is_err());
    }
    #[test]
    fn diagnostics_never_echo_account_provider_bodies_or_secrets() {
        for status in [400, 401, 409, 429, 503, 500] {
            let message = status_error(status);
            assert!(message.contains(&status.to_string()));
            assert!(!message.contains("ctf_"));
        }
    }
}
