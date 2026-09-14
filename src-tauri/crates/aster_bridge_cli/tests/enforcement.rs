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
#![cfg(feature = "test-support")]

mod support;

use std::time::Duration;

use support::mock_backend::{CodeStatus, Plan, SyncMode, TEST_EMAIL};
use support::{port_open, wait_until, Env, READY_TIMEOUT};

#[test]
fn login_links_the_device_and_records_the_plan() {
    let env = Env::new();
    let run = env.json(&["login"]);
    run.expect(0);
    let body = run.json();
    assert_eq!(body["status"], "signed_in");
    assert_eq!(body["account"]["email"], TEST_EMAIL);
    assert_eq!(body["plan"]["has_bridge_access"], true);

    let requests = env.mock.code_requests();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.client_header.as_deref(), Some("aster-bridge"));
    assert!(request
        .user_agent
        .as_deref()
        .is_some_and(|agent| agent.starts_with("AsterBridge/")));
    assert!(request.body["machine_name"]
        .as_str()
        .is_some_and(|name| name.ends_with("(CLI)")));
    for key in ["ed25519_pk", "mlkem_pk", "x25519_pk"] {
        assert!(request.body[key].as_str().is_some_and(|v| !v.is_empty()));
    }

    let status = env.json(&["status"]);
    status.expect(3);
    let status = status.json();
    assert_eq!(status["signed_in"], true);
    assert_eq!(status["running"], false);
    assert_eq!(status["account"]["email"], TEST_EMAIL);

    let again = env.json(&["login"]);
    again.expect(0);
    assert_eq!(again.json()["already_signed_in"], true);
    assert_eq!(env.mock.code_requests().len(), 1);
}

#[test]
fn expired_code_stores_nothing() {
    let env = Env::new();
    env.mock.set_code_status(CodeStatus::Expired);
    let run = env.json(&["login"]);
    run.expect(5);
    assert_eq!(run.error_code(), "code_expired");
    let status = env.json(&["status"]);
    status.expect(3);
    assert_eq!(status.json()["signed_in"], false);
}

#[test]
fn withdrawn_code_counts_as_expired() {
    let env = Env::new();
    env.mock.set_code_status(CodeStatus::Gone);
    let run = env.json(&["login"]);
    run.expect(5);
    assert_eq!(run.error_code(), "code_expired");
}

#[test]
fn login_no_wait_prints_the_code() {
    let env = Env::new();
    env.mock.set_code_status(CodeStatus::Pending);
    let run = env.json(&["login", "--no-wait"]);
    run.expect(0);
    let body = run.json();
    assert_eq!(body["status"], "pending");
    assert!(body["code"].as_str().is_some_and(|code| !code.is_empty()));
}

#[test]
fn plan_without_bridge_blocks_login_serve_and_app_passwords() {
    let env = Env::new();
    env.mock.set_plan(Plan::Deny);
    let run = env.json(&["login"]);
    run.expect(4);
    assert_eq!(run.error_code(), "bridge_access_required");

    let status = env.json(&["status"]);
    status.expect(4);
    assert_eq!(status.json()["plan"]["has_bridge_access"], false);

    env.json(&["app-password", "create"]).expect(4);

    let imap = env.config_port("imap_port");
    let mut serve = env.serve(&[]);
    serve.expect_exit(4, Some("bridge_access_required"));
    assert!(!port_open(imap));
}

#[test]
fn serve_does_not_start_when_the_plan_check_fails() {
    let env = Env::new();
    env.login();
    env.mock.set_plan(Plan::Fail);
    let imap = env.config_port("imap_port");
    let mut serve = env.serve(&[]);
    serve.expect_exit(1, Some("plan_check_failed"));
    assert!(env.mock.plan_calls() >= 3);
    assert!(!port_open(imap));
}

#[test]
fn serve_stops_when_the_plan_is_downgraded() {
    let env = Env::new();
    env.login();
    let mut serve = env.serve(&[]);
    let ready = serve.wait_event("ready", READY_TIMEOUT);
    assert_eq!(ready["account"], TEST_EMAIL);
    let imap = env.config_port("imap_port");
    assert!(port_open(imap));

    env.mock.set_plan(Plan::Deny);
    serve.expect_exit(4, Some("bridge_access_required"));
    assert!(serve.seen.iter().any(|v| v["event"] == "access_revoked"));
    assert!(wait_until(Duration::from_secs(5), || !port_open(imap)));

    let status = env.json(&["status"]);
    status.expect(4);
    assert_eq!(status.json()["plan"]["has_bridge_access"], false);
}

#[test]
fn serve_stops_when_sync_reports_an_upgrade_is_required() {
    let env = Env::new();
    env.login();
    let mut serve = env.serve(&[]);
    serve.wait_event("ready", READY_TIMEOUT);
    env.mock.set_sync(SyncMode::UpgradeRequired);
    serve.expect_exit(4, Some("bridge_access_required"));
}

#[test]
fn removed_device_is_signed_out() {
    let env = Env::new();
    env.login();
    env.mock.set_login_status(401);
    let mut serve = env.serve(&[]);
    serve.expect_exit(5, Some("device_revoked"));
    let status = env.json(&["status"]);
    status.expect(3);
    assert_eq!(status.json()["signed_in"], false);
}

#[test]
fn only_one_bridge_runs_per_data_folder_and_logout_stops_it() {
    let env = Env::new();
    env.login();
    let mut serve = env.serve(&[]);
    serve.wait_event("ready", READY_TIMEOUT);

    let status = env.json(&["status"]);
    status.expect(0);
    let status = status.json();
    assert_eq!(status["running"], true);
    assert!(status["services"].as_array().is_some_and(|s| !s.is_empty()));

    let second = env.json(&["serve"]);
    second.expect(7);
    assert_eq!(second.error_code(), "locked");

    env.json(&["outbox", "retry"]).expect(0);
    env.json(&["sync", "now"]).expect(0);

    let logout = env.json(&["logout"]);
    logout.expect(0);
    assert_eq!(logout.json()["was_signed_in"], true);
    serve.expect_exit(0, None);
    assert!(serve.seen.iter().any(|v| v["event"] == "stopped"));

    let status = env.json(&["status"]);
    status.expect(3);
    assert_eq!(status.json()["signed_in"], false);
}

#[test]
fn service_mode_retries_transient_failures_but_not_denials() {
    let env = Env::new();
    env.login();
    env.mock.set_plan(Plan::Fail);
    let mut serve = env.serve(&["--service"]);
    assert!(wait_until(Duration::from_secs(30), || env.mock.plan_calls() >= 6));
    env.mock.set_plan(Plan::Allow);
    serve.wait_event("ready", READY_TIMEOUT);
    env.mock.set_plan(Plan::Deny);
    serve.expect_exit(4, None);
}

#[test]
fn service_mode_exits_when_the_plan_is_denied() {
    let env = Env::new();
    env.login();
    env.mock.set_plan(Plan::Deny);
    let mut serve = env.serve(&["--service"]);
    serve.expect_exit(4, Some("bridge_access_required"));
    assert!(env.mock.plan_calls() <= 3);
}

#[test]
fn config_rejects_unsafe_ports() {
    let env = Env::new();
    let before = env.config_port("imap_port");
    env.json(&["config", "set", "imap_port", "80"]).expect(2);
    env.json(&["config", "set", "smtp_port", "5432"]).expect(2);
    env.json(&["config", "set", "imap_port", "not-a-port"]).expect(2);
    let smtp = env.config_port("smtp_port").to_string();
    env.json(&["config", "set", "imap_port", &smtp]).expect(2);
    env.json(&["config", "set", "no_such_key", "1"]).expect(2);
    assert_eq!(env.config_port("imap_port"), before);

    let get = env.json(&["config", "get", "imap_port"]);
    get.expect(0);
    assert_eq!(get.json()["value"], before);

    env.json(&["config", "set", "poll_interval_secs", "60"]).expect(0);
    assert_eq!(env.config_port("poll_interval_secs"), 60);
}

#[test]
fn app_passwords_work_offline_and_through_a_running_bridge() {
    let env = Env::new();
    env.login();

    let created = env.json(&["app-password", "create", "--label", "Laptop"]);
    created.expect(0);
    let created = created.json();
    let first_id = created["id"].as_str().unwrap().to_string();
    let first_password = created["password"].as_str().unwrap().to_string();
    assert_eq!(created["label"], "Laptop");
    assert!(first_password.len() >= 16);

    let listed = env.json(&["app-password", "list"]);
    listed.expect(0);
    assert!(!listed.stdout.contains(&first_password));
    assert!(listed.json()["app_passwords"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry["id"] == first_id.as_str()));

    let mut serve = env.serve(&[]);
    serve.wait_event("ready", READY_TIMEOUT);

    let second = env.json(&["app-password", "create", "--label", "Phone"]);
    second.expect(0);
    let second = second.json();
    let second_password = second["password"].as_str().unwrap().to_string();

    env.json(&["app-password", "revoke", &first_id]).expect(0);
    env.json(&["app-password", "revoke", &first_id]).expect(1);
    let listed = env.json(&["app-password", "list"]).json();
    let entries = listed["app_passwords"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["label"], "Phone");

    env.json(&["logout", "--keep-cache"]).expect(0);
    serve.expect_exit(0, None);

    let logs = env.log_text();
    assert!(!logs.is_empty());
    assert!(!logs.contains(&first_password));
    assert!(!logs.contains(&second_password));
    assert!(!logs.contains("mock-access-token"));
    assert!(!logs.contains("mock-refresh-token"));
}

#[test]
fn tls_fingerprint_is_stable() {
    let env = Env::new();
    let first = env.json(&["tls", "fingerprint"]);
    first.expect(0);
    let first = first.json();
    let second = env.json(&["tls", "fingerprint"]).json();
    assert_eq!(first["sha256"], second["sha256"]);
    let expected = aster_bridge_core::tls::cert_fingerprint_sha256(&env.data).unwrap();
    assert_eq!(first["sha256"], expected.as_str());
}

#[test]
fn commands_explain_what_they_need() {
    let env = Env::new();
    env.json(&["outbox", "list"]).expect(3);
    env.json(&["sync", "now"]).expect(3);
    env.json(&["serve"]).expect(3);
    env.json(&["app-password", "list"]).expect(3);

    env.login();
    let retry = env.json(&["outbox", "retry"]);
    retry.expect(3);
    assert_eq!(retry.error_code(), "not_running");
    let outbox = env.json(&["outbox", "list"]);
    outbox.expect(0);
    env.json(&["sync", "now"]).expect(3);
    env.run(&["no-such-command"]).expect(2);
}

#[test]
fn logout_removes_the_account_and_keys() {
    let env = Env::new();
    env.login();
    let logout = env.json(&["logout"]);
    logout.expect(0);
    let body = logout.json();
    assert_eq!(body["signed_in"], false);
    assert_eq!(body["was_signed_in"], true);
    assert!(!env.data.join("secrets").exists());
    assert!(!env.data.join("secret_backend").exists());

    let status = env.json(&["status"]);
    status.expect(3);
    assert_eq!(status.json()["signed_in"], false);

    env.login();
    assert_eq!(env.mock.code_requests().len(), 2);
}
