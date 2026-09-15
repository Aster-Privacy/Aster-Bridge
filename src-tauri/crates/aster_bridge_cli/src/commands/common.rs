//
// Aster Communications Inc.
//
// Copyright (c) 2026 Aster Communications Inc.
//
// This file is part of this project.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
//
use std::path::Path;
use std::sync::Arc;

use aster_bridge_core::account_state::{self, AccountState};
use aster_bridge_core::api_client::{ApiClient, PlanInfoResponse};
use aster_bridge_core::auth::app_passwords::{generate_app_password, AppPasswords};
use aster_bridge_core::auth::device_identity;
use aster_bridge_core::auth::session::{self, Session};
use aster_bridge_core::config::{self, BridgeConfig};
use aster_bridge_core::db::Database;
use aster_bridge_core::error::BridgeError;
use aster_bridge_core::runtime;
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::context::{self, Context};
use crate::exit::{
    CliError, CliResult, CODE_APP_PASSWORD_REVOKE, CODE_APP_PASSWORD_SAVE, CODE_INTERNAL,
    CODE_NETWORK, CODE_OUTBOX_READ, CODE_PLAN_CHECK, CODE_SETTINGS_READ, CODE_SIGN_IN,
    EXIT_ACCESS, EXIT_ERROR, UPGRADE_URL,
};
use crate::lock::InstanceLock;
use crate::output::title_case;
use crate::secret_backend::{self, is_secret_error, map_store_error};
use crate::state::{self, CliState, PlanInfo};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const APP_URL: &str = "https://app.astermail.org";
const MAX_LABEL_CHARS: usize = 64;
const DEFAULT_LABEL: &str = "App Password";

pub fn require_account(data_dir: &Path) -> CliResult<CliState> {
    let state = state::load(data_dir);
    if state.account.is_none() || !secret_backend::has_record(data_dir) {
        return Err(CliError::not_signed_in());
    }
    Ok(state)
}

pub fn signed_in_state(ctx: &Context) -> CliResult<CliState> {
    let state = require_account(&ctx.data_dir)?;
    match secret_backend::activate_existing(&ctx.data_dir, ctx.global.secret_backend)? {
        Some(_) => Ok(state),
        None => Err(CliError::not_signed_in()),
    }
}

pub fn save_state(data_dir: &Path, f: impl FnOnce(&mut CliState)) {
    if let Err(e) = state::update(data_dir, f) {
        tracing::warn!("couldn't save state: {}", e);
    }
}

pub fn forget_device(data_dir: &Path) {
    let _ = device_identity::clear_device_id(data_dir);
    device_identity::clear_passphrase(data_dir);
    state::clear_pending(data_dir);
    save_state(data_dir, |s| {
        s.account = None;
        s.plan = None;
        s.ports = None;
    });
}

pub fn load_config() -> CliResult<BridgeConfig> {
    config::load_config()
        .map_err(|e| CliError::coded(CODE_SETTINGS_READ, format!("Couldn't read the settings file: {}", e)))
}

pub fn plan_label(code: Option<&str>) -> String {
    match code.map(str::trim).filter(|c| !c.is_empty()) {
        Some(code) => title_case(&code.replace(['_', '-'], " ")),
        None => "Unknown".to_string(),
    }
}

pub fn access_denied(plan_code: Option<&str>) -> CliError {
    let message = match plan_code.map(str::trim).filter(|c| !c.is_empty()) {
        Some(code) => format!(
            "Your {} plan doesn't include Aster Bridge, which needs a Star plan or higher.",
            plan_label(Some(code))
        ),
        None => "Your plan doesn't include Aster Bridge, which needs a Star plan or higher.".to_string(),
    };
    CliError::access_required(message)
}

pub fn upgrade_then_refresh_hint() -> String {
    format!(
        "To use Aster Bridge, upgrade your plan at {}. After you upgrade, run: aster-bridge status --refresh",
        UPGRADE_URL
    )
}

pub fn account_state_label(account_state: AccountState) -> &'static str {
    match account_state {
        AccountState::Active => "Active",
        AccountState::Suspended => "Suspended",
        AccountState::DeletionScheduled => "Scheduled for deletion",
        AccountState::FamilyPolicy => "Needs two-factor authentication",
    }
}

pub fn account_state_error(account_state: AccountState) -> CliError {
    let (message, hint) = match account_state {
        AccountState::Suspended => (
            "Your Aster Mail account is suspended, so Aster Bridge can't connect.",
            format!("To learn more, sign in at {}.", APP_URL),
        ),
        AccountState::DeletionScheduled => (
            "Your Aster Mail account is scheduled for deletion, so Aster Bridge can't connect.",
            format!("To keep your account, cancel the deletion at {}.", APP_URL),
        ),
        AccountState::FamilyPolicy => (
            "Your family plan requires two-factor authentication before Aster Bridge can connect.",
            format!("To continue, turn on two-factor authentication at {}/settings.", APP_URL),
        ),
        AccountState::Active => {
            return CliError::coded(CODE_SIGN_IN, "Aster Mail refused the sign-in.");
        }
    };
    CliError::new(EXIT_ACCESS, account_state.as_str(), message).with_hint(hint)
}

pub fn network_error(detail: &str) -> CliError {
    CliError::new(EXIT_ERROR, CODE_NETWORK, "Couldn't reach Aster Mail.").with_hint(format!(
        "Check your internet connection and try again. Details: {}",
        detail
    ))
}

pub fn map_login_error(data_dir: &Path, error: BridgeError) -> CliError {
    let text = error.to_string();
    if let Some(account_state) = account_state::classify(&text) {
        save_state(data_dir, |s| s.account_state = account_state);
        return account_state_error(account_state);
    }
    if runtime::is_definitive_device_failure(&error) {
        forget_device(data_dir);
        return CliError::device_revoked();
    }
    match error {
        BridgeError::PlanUpgradeRequired(_) => access_denied(None),
        BridgeError::Auth(message) if message.contains("first-time setup required") => {
            CliError::not_signed_in()
        }
        BridgeError::Auth(message) | BridgeError::Crypto(message) if is_secret_error(&message) => {
            map_store_error("Couldn't read the device keys", message)
        }
        BridgeError::Network(e) => network_error(&e.to_string()),
        other => CliError::coded(CODE_SIGN_IN, format!("Couldn't sign in to Aster Mail: {}", other)),
    }
}

pub struct Offline {
    _lock: InstanceLock,
    pub db: Arc<Database>,
    pub state: CliState,
}

pub fn open_offline(ctx: &Context) -> CliResult<Offline> {
    let lock = InstanceLock::acquire(&ctx.data_dir)?;
    let state = signed_in_state(ctx)?;
    let db = Database::open(&ctx.data_dir)
        .map_err(|e| map_store_error("Couldn't open the mail cache", e))?;
    Ok(Offline {
        _lock: lock,
        db: Arc::new(db),
        state,
    })
}

pub async fn call_or_offline<F>(ctx: &Context, op: &str, args: Value, offline: F) -> CliResult<Value>
where
    F: FnOnce(&Offline) -> CliResult<Value> + Send + 'static,
{
    if let Some(value) = crate::control::call_running(&ctx.data_dir, op, args).await? {
        return Ok(value);
    }
    let handle = open_offline(ctx)?;
    tokio::task::spawn_blocking(move || offline(&handle))
        .await
        .map_err(|e| CliError::coded(CODE_INTERNAL, e.to_string()))?
}

pub async fn sign_in_offline(ctx: &Context) -> CliResult<(ApiClient, Session)> {
    let config = load_config()?;
    let identity = device_identity::get_or_create_identity(&ctx.data_dir)
        .map_err(|e| map_store_error("Couldn't load the device identity", e))?;
    if identity.device_id.is_none() {
        return Err(CliError::not_signed_in());
    }
    let client = context::api_client();
    let session = session::restore_or_login(&config, &identity, &client)
        .await
        .map_err(|e| map_login_error(&ctx.data_dir, e))?;
    save_state(&ctx.data_dir, |s| s.account_state = AccountState::Active);
    Ok((client, session))
}

pub fn plan_is_fresh(state: &CliState) -> bool {
    let limit = context::refresh_rate_limit().as_secs() as i64;
    limit > 0
        && state
            .plan
            .as_ref()
            .is_some_and(|plan| state::now() - plan.checked_at < limit)
}

pub fn plan_from_result(
    previous: Option<&PlanInfo>,
    result: Result<PlanInfoResponse, BridgeError>,
) -> CliResult<PlanInfo> {
    match result {
        Ok(info) => Ok(PlanInfo {
            code: Some(info.plan_code),
            has_bridge_access: info.has_bridge_access,
            checked_at: state::now(),
        }),
        Err(BridgeError::PlanUpgradeRequired(_)) => Ok(PlanInfo {
            code: previous.and_then(|p| p.code.clone()),
            has_bridge_access: false,
            checked_at: state::now(),
        }),
        Err(BridgeError::Network(e)) => Err(network_error(&e.to_string())),
        Err(e) => Err(CliError::coded(CODE_PLAN_CHECK, format!("Couldn't check your plan: {}", e))),
    }
}

pub fn ensure_plan_allows_bridge(state: &CliState) -> CliResult<()> {
    match &state.plan {
        Some(plan) if !plan.has_bridge_access => {
            Err(access_denied(plan.code.as_deref()).with_hint(upgrade_then_refresh_hint()))
        }
        _ => Ok(()),
    }
}

pub fn clean_label(label: Option<&str>) -> CliResult<String> {
    let label = label.map(str::trim).unwrap_or("");
    if label.chars().any(char::is_control) {
        return Err(CliError::usage("App password labels can't contain control characters."));
    }
    if label.chars().count() > MAX_LABEL_CHARS {
        return Err(CliError::usage(format!(
            "App password labels can be up to {} characters.",
            MAX_LABEL_CHARS
        )));
    }
    Ok(if label.is_empty() {
        DEFAULT_LABEL.to_string()
    } else {
        label.to_string()
    })
}

pub fn app_password_create(
    passwords: &AppPasswords,
    state: &CliState,
    label: Option<&str>,
) -> CliResult<Value> {
    ensure_plan_allows_bridge(state)?;
    let label = clean_label(label)?;
    let password = Zeroizing::new(generate_app_password());
    let id = passwords
        .store(&label, &password)
        .map_err(|e| CliError::coded(CODE_APP_PASSWORD_SAVE, format!("Couldn't save the app password: {}", e)))?;
    Ok(json!({ "id": id, "label": label, "password": password.as_str() }))
}

pub fn app_password_list(passwords: &AppPasswords) -> Value {
    let items: Vec<Value> = passwords
        .list()
        .into_iter()
        .map(|entry| {
            json!({
                "id": entry.id,
                "label": entry.label,
                "created_at": entry.created_at,
                "last_used_at": entry.last_used_at,
                "last_client": entry.last_client,
                "use_count": entry.use_count,
            })
        })
        .collect();
    json!({ "app_passwords": items })
}

pub fn app_password_revoke(passwords: &AppPasswords, id: &str) -> CliResult<Value> {
    let id = id.trim();
    if !passwords.list().iter().any(|entry| entry.id == id) {
        return Err(CliError::new(
            EXIT_ERROR,
            crate::exit::CODE_NOT_FOUND,
            format!("No app password has the ID {}.", id),
        )
        .with_hint("To see your app passwords and their IDs, run: aster-bridge app-password list"));
    }
    passwords
        .delete(id)
        .map_err(|e| CliError::coded(CODE_APP_PASSWORD_REVOKE, format!("Couldn't revoke the app password: {}", e)))?;
    Ok(json!({ "revoked": id }))
}

fn parse_subject(raw_mime: &[u8]) -> Option<String> {
    mail_parser::MessageParser::default()
        .parse(raw_mime)
        .and_then(|message| message.subject().map(str::to_string))
}

pub fn outbox_list(db: &Database) -> CliResult<Value> {
    let rows = db
        .outbox_list_pending()
        .map_err(|e| CliError::coded(CODE_OUTBOX_READ, format!("Couldn't read the outbox: {}", e)))?;
    let items: Vec<Value> = rows
        .into_iter()
        .map(|row| {
            json!({
                "id": row.id,
                "from": row.envelope_from,
                "to": row.envelope_to,
                "subject": parse_subject(&row.raw_mime),
                "size": row.raw_mime.len(),
                "queued_at": row.queued_at,
                "attempts": row.attempts,
                "last_attempt_at": row.last_attempt_at,
                "last_error": row.last_error,
                "status": row.status,
            })
        })
        .collect();
    Ok(json!({ "messages": items }))
}

pub fn security_label(security: &str) -> &'static str {
    match security {
        "starttls" => "STARTTLS",
        "tls" => "SSL/TLS",
        "https" => "HTTPS",
        "http" => "HTTP",
        _ => "None",
    }
}

pub fn truncate(text: &str, max: usize) -> String {
    let single_line = text.replace(['\r', '\n', '\t'], " ");
    if single_line.chars().count() <= max {
        return single_line;
    }
    let cut: String = single_line.chars().take(max.saturating_sub(3)).collect();
    format!("{}...", cut.trim_end())
}

pub fn plural(count: usize, one: &str, many: &str) -> String {
    if count == 1 {
        format!("{} {}", count, one)
    } else {
        format!("{} {}", count, many)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_labels_are_readable() {
        assert_eq!(plan_label(Some("star")), "Star");
        assert_eq!(plan_label(Some("nova_family")), "Nova family");
        assert_eq!(plan_label(None), "Unknown");
        assert_eq!(
            access_denied(Some("free")).message,
            "Your Free plan doesn't include Aster Bridge, which needs a Star plan or higher."
        );
    }

    #[test]
    fn labels_are_validated() {
        assert_eq!(clean_label(None).unwrap(), DEFAULT_LABEL);
        assert_eq!(clean_label(Some("  Phone ")).unwrap(), "Phone");
        assert!(clean_label(Some("a\nb")).is_err());
        assert!(clean_label(Some(&"x".repeat(65))).is_err());
    }

    #[test]
    fn cached_denial_blocks_new_app_passwords() {
        let mut state = CliState::default();
        assert!(ensure_plan_allows_bridge(&state).is_ok());
        state.plan = Some(PlanInfo {
            code: Some("free".into()),
            has_bridge_access: false,
            checked_at: 0,
        });
        assert_eq!(
            ensure_plan_allows_bridge(&state).unwrap_err().exit_code,
            EXIT_ACCESS
        );
    }

    #[test]
    fn device_failures_map_to_revoked() {
        let dir = tempfile::tempdir().unwrap();
        let err = map_login_error(dir.path(), BridgeError::Api("404 Not Found: gone".into()));
        assert_eq!(err.code, "device_revoked");
        let err = map_login_error(
            dir.path(),
            BridgeError::Api("403 Forbidden: ACCOUNT_SUSPENDED".into()),
        );
        assert_eq!(err.exit_code, EXIT_ACCESS);
        let err = map_login_error(dir.path(), BridgeError::PlanUpgradeRequired("x".into()));
        assert_eq!(err.code, "bridge_access_required");
    }

    #[test]
    fn truncate_keeps_short_text() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello world", 8), "hello...");
    }
}
