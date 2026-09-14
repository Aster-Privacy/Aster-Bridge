//
// Aster Communications Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//
use std::collections::VecDeque;
use std::path::{Path, PathBuf};

const LOG_FILENAME_PREFIX: &str = "bridge.log";
const MAX_RECENT_LINES: usize = 500;
const MAX_KEEP_DAYS: usize = 7;

pub fn log_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("logs")
}

pub fn current_log_path(data_dir: &Path) -> PathBuf {
    let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
    log_dir(data_dir).join(format!("{}.{}", LOG_FILENAME_PREFIX, date))
}

pub fn ensure_log_dir(data_dir: &Path) -> std::io::Result<PathBuf> {
    let dir = log_dir(data_dir);
    std::fs::create_dir_all(&dir)?;
    restrict_dir_permissions(&dir);
    Ok(dir)
}

fn restrict_dir_permissions(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        if let Ok(user) = std::env::var("USERNAME") {
            if !user.is_empty() {
                let _ = std::process::Command::new("icacls")
                    .args([
                        &dir.to_string_lossy().to_string(),
                        "/inheritance:r",
                        "/grant:r",
                        &format!("{}:(OI)(CI)F", user),
                    ])
                    .creation_flags(0x0800_0000)
                    .output();
            }
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = dir;
    }
}

pub fn prune_old_logs(data_dir: &Path) {
    let dir = log_dir(data_dir);
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    let mut files: Vec<(std::time::SystemTime, PathBuf)> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let path = e.path();
            let name = path.file_name()?.to_string_lossy().to_string();
            if !name.starts_with(LOG_FILENAME_PREFIX) {
                return None;
            }
            let mtime = e.metadata().ok()?.modified().ok()?;
            Some((mtime, path))
        })
        .collect();
    files.sort_by(|a, b| b.0.cmp(&a.0));
    for (_, path) in files.into_iter().skip(MAX_KEEP_DAYS) {
        let _ = std::fs::remove_file(path);
    }
}

pub fn read_recent_lines(data_dir: &Path) -> Vec<String> {
    let path = current_log_path(data_dir);
    let contents = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let mut window: VecDeque<String> = VecDeque::with_capacity(MAX_RECENT_LINES);
    for line in contents.lines() {
        if window.len() == MAX_RECENT_LINES {
            window.pop_front();
        }
        window.push_back(redact_line(line));
    }
    window.into_iter().collect()
}

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '@' | '.' | '_' | '-' | '+' | '/' | '=')
}

fn looks_like_email(tok: &str) -> bool {
    match tok.split_once('@') {
        Some((local, domain)) => {
            !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
        }
        None => false,
    }
}

fn looks_like_app_password(tok: &str) -> bool {
    let groups: Vec<&str> = tok.split('-').collect();
    groups.len() == 4
        && groups
            .iter()
            .all(|g| g.len() == 4 && g.chars().all(|c| c.is_ascii_alphanumeric()))
}

fn looks_like_secret_blob(tok: &str) -> bool {
    tok.len() >= 24
        && tok.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '_' | '-' | '.'))
        && tok.chars().any(|c| c.is_ascii_alphanumeric())
}

const SENSITIVE_KEYS: &[&str] = &[
    "password", "passwd", "passphrase", "secret", "token", "apikey", "api_key",
    "authorization", "cookie", "credential", "access_token", "refresh_token", "bearer",
];

fn redact_token(tok: &str) -> Option<String> {
    if looks_like_email(tok) {
        return Some("[redacted-email]".to_string());
    }
    if looks_like_app_password(tok) || looks_like_secret_blob(tok) {
        return Some("[redacted-secret]".to_string());
    }
    // Inline `key=value` secrets (e.g. access_token=abc123) keep the key, redact the value.
    if let Some((key, value)) = tok.split_once('=') {
        if !value.is_empty() && SENSITIVE_KEYS.contains(&key.to_ascii_lowercase().as_str()) {
            return Some(format!("{}=[redacted-secret]", key));
        }
    }
    None
}

pub(crate) fn redact_line(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut token = String::new();
    let mut redact_next = false;
    let flush = |out: &mut String, token: &mut String, redact_next: &mut bool| {
        if token.is_empty() {
            return;
        }
        if *redact_next {
            out.push_str("[redacted-secret]");
        } else if let Some(r) = redact_token(token) {
            out.push_str(&r);
        } else {
            out.push_str(token);
        }
        // `Bearer <token>`: the value follows in the next token.
        *redact_next = token.eq_ignore_ascii_case("bearer");
        token.clear();
    };
    for c in line.chars() {
        if is_token_char(c) {
            token.push(c);
        } else {
            flush(&mut out, &mut token, &mut redact_next);
            out.push(c);
        }
    }
    flush(&mut out, &mut token, &mut redact_next);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_email_addresses() {
        let out = redact_line("delivering to alice@example.com now");
        assert!(!out.contains("alice@example.com"));
        assert!(out.contains("[redacted-email]"));
        assert!(out.contains("delivering to") && out.contains("now"));
    }

    #[test]
    fn redacts_app_password_and_bearer_token() {
        let out = redact_line("PASS abcd-ef23-ghij-k4mn for user");
        assert!(!out.contains("abcd-ef23-ghij-k4mn"));
        let jwt = "eyJhbGciOiJIUzI1NiwidHlwIjoiSldUIn0.payloadpayloadpayload.sig";
        let out2 = redact_line(&format!("Authorization Bearer {}", jwt));
        assert!(!out2.contains(jwt));
        assert!(out2.contains("[redacted-secret]"));
    }

    #[test]
    fn preserves_ordinary_text() {
        let line = "IMAP server listening on 127.0.0.1:1143 (STARTTLS=true)";
        assert_eq!(redact_line(line), line);
    }
}
