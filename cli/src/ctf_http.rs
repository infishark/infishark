//! Shared CTF JSON transport: bounded responses, no redirects, static errors.

use std::io::Read;
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{Result, bail};
use serde_json::Value;

pub(crate) const USER_AGENT: &str = concat!("infishark-cli/", env!("CARGO_PKG_VERSION"));
pub(crate) const MAX_RESPONSE: u64 = 128 * 1024;

pub(crate) fn agent() -> ureq::Agent {
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    // Clones share the pool. Credentials stay on individual requests.
    AGENT
        .get_or_init(|| {
            ureq::AgentBuilder::new()
                .redirects(0)
                .timeout_connect(Duration::from_secs(15))
                .timeout(Duration::from_secs(30))
                .build()
        })
        .clone()
}

pub(crate) fn request(req: ureq::Request, body: Option<&Value>) -> Result<ureq::Response> {
    let req = req.set("User-Agent", USER_AGENT);
    let result = match body {
        Some(body) => req
            .set("Content-Type", "application/json")
            .send_string(&body.to_string()),
        None => req.call(),
    };
    match result {
        Ok(response) | Err(ureq::Error::Status(_, response)) => Ok(response),
        // Transport diagnostics may embed URLs or headers; never echo them.
        Err(_) => bail!("CTF request failed; check the API URL and connection"),
    }
}

pub(crate) fn read_body(response: ureq::Response, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow::anyhow!("could not read CTF response"))?;
    if bytes.len() as u64 > limit {
        bail!("CTF response is too large");
    }
    Ok(bytes)
}

fn json_response(req: ureq::Request, body: Option<&Value>) -> Result<(u16, String)> {
    let response = request(req, body)?;
    let status = response.status();
    // Failure bodies are neither parsed nor printed, including from proxies.
    if status != 200 {
        return Ok((status, String::new()));
    }
    let bytes = read_body(response, MAX_RESPONSE)?;
    let text =
        String::from_utf8(bytes).map_err(|_| anyhow::anyhow!("CTF response is not valid UTF-8"))?;
    Ok((status, text))
}

pub(crate) fn send(req: ureq::Request) -> Result<(u16, String)> {
    json_response(req, None)
}

pub(crate) fn send_json(req: ureq::Request, body: Value) -> Result<(u16, String)> {
    json_response(req, Some(&body))
}
