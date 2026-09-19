//! `state/gateway.json` (SPECS §2.1). Locally generated; mode 0600 is the
//! caller's job. This crate only shapes the bytes.

use crate::sigv4::Creds;
use std::fmt;

#[derive(Debug)]
pub enum CredsError {
    Parse,
    MissingField(&'static str),
}

impl fmt::Display for CredsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse => write!(
                f,
                "gateway.json is not the two-field object this build writes"
            ),
            Self::MissingField(s) => write!(f, "gateway.json missing {s}"),
        }
    }
}

/// Access keys are hex so the file is printable and a typo is obvious.
pub fn generate(seed_ak: &[u8; 16], seed_sk: &[u8; 32]) -> Creds {
    Creds {
        access_key_id: crate::hmac::hex_encode(seed_ak),
        secret_access_key: crate::hmac::hex_encode(seed_sk),
    }
}

pub fn encode(c: &Creds) -> String {
    format!(
        "{{\"access_key_id\":\"{}\",\"secret_access_key\":\"{}\"}}\n",
        c.access_key_id, c.secret_access_key
    )
}

pub fn decode(bytes: &[u8]) -> Result<Creds, CredsError> {
    let s = std::str::from_utf8(bytes).map_err(|_| CredsError::Parse)?;
    let ak = json_string(s, "access_key_id").ok_or(CredsError::MissingField("access_key_id"))?;
    let sk =
        json_string(s, "secret_access_key").ok_or(CredsError::MissingField("secret_access_key"))?;
    if ak.is_empty() || sk.is_empty() {
        return Err(CredsError::Parse);
    }
    Ok(Creds {
        access_key_id: ak,
        secret_access_key: sk,
    })
}

fn json_string(s: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let rest = s.split_once(&needle)?.1;
    let rest = rest.trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let (v, _) = rest.split_once('"')?;
    Some(v.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_round_trips() {
        let c = generate(&[1u8; 16], &[2u8; 32]);
        assert_eq!(c.access_key_id.len(), 32);
        assert_eq!(c.secret_access_key.len(), 64);
        let back = decode(encode(&c).as_bytes()).unwrap();
        assert_eq!(back.access_key_id, c.access_key_id);
        assert_eq!(back.secret_access_key, c.secret_access_key);
    }

    #[test]
    fn a_missing_secret_is_refused() {
        assert!(decode(br#"{"access_key_id":"aa"}"#).is_err());
    }
}
