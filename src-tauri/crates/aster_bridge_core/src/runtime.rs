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
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::time::Duration;

use tokio::sync::{mpsc, watch, RwLock};
use tokio::task::JoinHandle;

use crate::api_client::ApiClient;
use crate::auth::app_passwords::AppPasswords;
use crate::auth::session::Session;
use crate::config::BridgeConfig;
use crate::db::Database;
use crate::error::BridgeError;
use crate::port_picker::{self, Occupant};
use crate::sync::poller::{self, PollExit, PollTuning, SyncTrigger, SyncTriggerTx};

pub const LOOPBACK_HOST: &str = "127.0.0.1";
const PLAN_CHECK_ATTEMPTS: u8 = 3;
const SESSION_EXPIRED_AFTER_FAILURES: u32 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Service {
    Imap,
    Imaps,
    Smtp,
    Smtps,
    Jmap,
    Carddav,
    Pop3,
    Pop3s,
    Sync,
    Gc,
    Outbox,
    TokenRefresh,
}

impl Service {
    pub fn label(self) -> &'static str {
        match self {
            Service::Imap => "IMAP",
            Service::Imaps => "IMAPS",
            Service::Smtp => "SMTP",
            Service::Smtps => "SMTPS",
            Service::Jmap => "JMAP",
            Service::Carddav => "CardDAV",
            Service::Pop3 => "POP3",
            Service::Pop3s => "POP3S",
            Service::Sync => "sync",
            Service::Gc => "cache cleanup",
            Service::Outbox => "outbox",
            Service::TokenRefresh => "session refresh",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "reason", content = "detail", rename_all = "snake_case")]
pub enum StopReason {
    UserRequested,
    AccessRevoked,
    DeviceRevoked,
    Fatal(String),
}

impl StopReason {
    pub fn code(&self) -> &'static str {
        match self {
            StopReason::UserRequested => "user_requested",
            StopReason::AccessRevoked => "access_revoked",
            StopReason::DeviceRevoked => "device_revoked",
            StopReason::Fatal(_) => "fatal",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartError {
    BridgeAccessRequired { plan_code: Option<String> },
    PlanCheckFailed(String),
    NotSignedIn,
    DeviceRevoked,
    PortUnavailable {
        service: Service,
        port: u16,
        message: String,
        held_by_bridge: bool,
    },
    Io(String),
    Database(String),
}

impl StartError {
    pub fn code(&self) -> &'static str {
        match self {
            StartError::BridgeAccessRequired { .. } => "bridge_access_required",
            StartError::PlanCheckFailed(_) => "plan_check_failed",
            StartError::NotSignedIn => "not_signed_in",
            StartError::DeviceRevoked => "device_revoked",
            StartError::PortUnavailable { .. } => "port_unavailable",
            StartError::Io(_) => "io",
            StartError::Database(_) => "database",
        }
    }
}

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StartError::BridgeAccessRequired { .. } => f.write_str("bridge_access_required"),
            StartError::PlanCheckFailed(e) => write!(f, "could not confirm your plan: {}", e),
            StartError::NotSignedIn => f.write_str("not authenticated - run setup first"),
            StartError::DeviceRevoked => f.write_str("this device was removed from your account"),
            StartError::PortUnavailable { message, .. } => f.write_str(message),
            StartError::Io(e) => f.write_str(e),
            StartError::Database(e) => f.write_str(e),
        }
    }
}

impl std::error::Error for StartError {}

#[derive(Debug, Clone)]
pub struct PlanGrant {
    plan_code: String,
}

impl PlanGrant {
    pub fn plan_code(&self) -> &str {
        &self.plan_code
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientProfile {
    Desktop,
    Cli,
}

#[derive(Debug, Clone, Copy)]
pub struct RuntimeTuning {
    pub poll: PollTuning,
    pub plan_retry_delay: Duration,
    pub token_refresh_interval: Duration,
    pub token_retry_interval: Duration,
    pub blob_gc_interval: Duration,
}

impl RuntimeTuning {
    pub fn for_config(config: &BridgeConfig) -> Self {
        Self {
            poll: PollTuning::from_interval_secs(Some(config.poll_interval_secs)),
            plan_retry_delay: Duration::from_secs(2),
            token_refresh_interval: Duration::from_secs(50 * 60),
            token_retry_interval: Duration::from_secs(60),
            blob_gc_interval: Duration::from_secs(3600),
        }
    }
}

pub async fn check_bridge_access(
    client: &ApiClient,
    session: &Arc<RwLock<Session>>,
    retry_delay: Duration,
) -> Result<PlanGrant, StartError> {
    let mut last_error = String::new();
    for attempt in 0..PLAN_CHECK_ATTEMPTS {
        if attempt > 0 {
            tokio::time::sleep(retry_delay).await;
        }
        let token = {
            let s = session.read().await;
            (*s.access_token).clone()
        };
        match client.get_plan_info(&token).await {
            Ok(info) if info.has_bridge_access => {
                return Ok(PlanGrant {
                    plan_code: info.plan_code,
                })
            }
            Ok(info) => {
                return Err(StartError::BridgeAccessRequired {
                    plan_code: Some(info.plan_code),
                })
            }
            Err(BridgeError::PlanUpgradeRequired(_)) => {
                return Err(StartError::BridgeAccessRequired { plan_code: None })
            }
            Err(e) => {
                tracing::warn!("plan check attempt {} failed: {}", attempt + 1, e);
                last_error = e.to_string();
            }
        }
    }
    Err(StartError::PlanCheckFailed(last_error))
}

pub fn is_definitive_device_failure(error: &BridgeError) -> bool {
    match error {
        BridgeError::Api(msg) => msg.starts_with("401") || msg.starts_with("404"),
        _ => false,
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct BoundPorts {
    pub imap: u16,
    pub smtp: u16,
    pub jmap: u16,
    pub carddav: u16,
    pub imaps: u16,
    pub smtps: u16,
    pub pop3: u16,
    pub pop3s: u16,
}

impl BoundPorts {
    pub fn apply_to_config(&self, config: &mut BridgeConfig) -> bool {
        let mut dirty = false;
        let mut update = |slot: &mut u16, value: u16| {
            if value != 0 && *slot != value {
                *slot = value;
                dirty = true;
            }
        };
        update(&mut config.imap_port, self.imap);
        update(&mut config.smtp_port, self.smtp);
        update(&mut config.jmap_port, self.jmap);
        update(&mut config.carddav_port, self.carddav);
        dirty
    }
}

pub struct RuntimeDeps {
    pub session: Arc<RwLock<Session>>,
    pub db: Arc<Database>,
    pub client: Arc<ApiClient>,
    pub passwords: Arc<AppPasswords>,
}

pub struct StartOptions {
    pub config: BridgeConfig,
    pub tls: Option<Arc<rustls::ServerConfig>>,
    pub device_id: uuid::Uuid,
    pub signing_key: ed25519_dalek::SigningKey,
    pub profile: ClientProfile,
    pub tuning: RuntimeTuning,
}

struct Inner {
    handles: StdMutex<Vec<(Service, JoinHandle<()>)>>,
    stop_tx: watch::Sender<Option<StopReason>>,
    sync_trigger: SyncTriggerTx,
}

impl Inner {
    fn stop(&self, reason: StopReason) {
        let mut first = false;
        self.stop_tx.send_if_modified(|current| {
            if current.is_none() {
                *current = Some(reason.clone());
                first = true;
                true
            } else {
                false
            }
        });
        let handles = match self.handles.lock() {
            Ok(mut guard) => std::mem::take(&mut *guard),
            Err(poisoned) => std::mem::take(&mut *poisoned.into_inner()),
        };
        for (_, handle) in handles {
            handle.abort();
        }
        if first {
            poller::clear_global_sync_trigger_if(&self.sync_trigger);
            tracing::info!("bridge stopped ({})", reason.code());
        }
    }
}

#[derive(Clone)]
pub struct RunningBridge {
    inner: Arc<Inner>,
    ports: BoundPorts,
    outbox_trigger: mpsc::Sender<i64>,
    stop_rx: watch::Receiver<Option<StopReason>>,
}

impl RunningBridge {
    pub fn bound_ports(&self) -> BoundPorts {
        self.ports
    }

    pub fn is_running(&self) -> bool {
        self.stop_rx.borrow().is_none()
    }

    pub fn stop_reason(&self) -> Option<StopReason> {
        self.stop_rx.borrow().clone()
    }

    pub fn service_running(&self, service: Service) -> bool {
        if !self.is_running() {
            return false;
        }
        match self.inner.handles.lock() {
            Ok(guard) => guard
                .iter()
                .any(|(s, h)| *s == service && !h.is_finished()),
            Err(_) => false,
        }
    }

    pub fn stop(&self, reason: StopReason) {
        self.inner.stop(reason);
    }

    pub async fn wait(&self) -> StopReason {
        let mut rx = self.stop_rx.clone();
        let reason = rx.wait_for(|v| v.is_some()).await.ok().and_then(|v| v.clone());
        reason.unwrap_or(StopReason::UserRequested)
    }

    pub fn sync_trigger(&self) -> Option<SyncTriggerTx> {
        self.is_running().then(|| self.inner.sync_trigger.clone())
    }

    pub fn outbox_trigger(&self) -> Option<mpsc::Sender<i64>> {
        self.is_running().then(|| self.outbox_trigger.clone())
    }

    pub async fn sync_now(&self) -> Result<(), String> {
        let trigger = self
            .sync_trigger()
            .ok_or_else(|| "bridge is not running".to_string())?;
        let (tx, rx) = tokio::sync::oneshot::channel();
        trigger
            .send(SyncTrigger { done: tx })
            .await
            .map_err(|_| "sync worker not available".to_string())?;
        match rx.await {
            Ok(result) => result,
            Err(_) => Err("sync worker dropped completion channel".to_string()),
        }
    }
}

struct PortPlan {
    ports: BoundPorts,
    jmap_enabled: bool,
    carddav_enabled: bool,
}

fn port_error(service: Service, port: u16, message: String) -> StartError {
    let held_by_bridge = matches!(
        port_picker::probe_occupant(LOOPBACK_HOST, port),
        Occupant::AsterBridge
    );
    StartError::PortUnavailable {
        service,
        port,
        message,
        held_by_bridge,
    }
}

fn plan_ports(config: &BridgeConfig, tls: bool) -> Result<PortPlan, StartError> {
    let host = LOOPBACK_HOST;
    let imap = port_picker::pick_startup_port(host, config.imap_port)
        .map_err(|e| port_error(Service::Imap, config.imap_port, e))?;
    let smtp = port_picker::pick_startup_port(host, config.smtp_port)
        .map_err(|e| port_error(Service::Smtp, config.smtp_port, e))?;
    let jmap = if config.jmap_enabled {
        port_picker::pick_available_port(host, config.jmap_port)
            .map_err(|e| port_error(Service::Jmap, config.jmap_port, e))?
    } else {
        0
    };
    let carddav = if config.carddav_enabled {
        match port_picker::pick_available_port(host, config.carddav_port) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("CardDAV listener disabled: {}", e);
                0
            }
        }
    } else {
        0
    };
    let pick_tls = |service: Service, preferred: u16| -> u16 {
        if !tls {
            return 0;
        }
        match port_picker::pick_startup_port(host, preferred) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("{} listener disabled: {}", service.label(), e);
                0
            }
        }
    };
    let imaps = pick_tls(Service::Imaps, config.imap_implicit_tls_port);
    let smtps = pick_tls(Service::Smtps, config.smtp_implicit_tls_port);
    let pop3 = port_picker::pick_available_port(host, config.pop3_port).unwrap_or(0);
    let pop3s = if tls {
        port_picker::pick_available_port(host, config.pop3s_port).unwrap_or(0)
    } else {
        0
    };
    Ok(PortPlan {
        ports: BoundPorts {
            imap,
            smtp,
            jmap,
            carddav,
            imaps,
            smtps,
            pop3,
            pop3s,
        },
        jmap_enabled: config.jmap_enabled,
        carddav_enabled: config.carddav_enabled && carddav != 0,
    })
}

type StopSender = mpsc::UnboundedSender<StopReason>;

fn spawn_listener<F, E>(service: Service, fatal: Option<StopSender>, fut: F) -> JoinHandle<()>
where
    F: std::future::Future<Output = Result<(), E>> + Send + 'static,
    E: std::fmt::Display + Send + 'static,
{
    tokio::spawn(async move {
        if let Err(e) = fut.await {
            tracing::error!("{} server error: {}", service.label(), e);
            if let Some(tx) = fatal {
                let _ = tx.send(StopReason::Fatal(format!(
                    "{} listener failed: {}",
                    service.label(),
                    e
                )));
            }
        }
    })
}

pub struct BridgeRuntime;

impl BridgeRuntime {
    pub async fn start(
        grant: PlanGrant,
        deps: RuntimeDeps,
        opts: StartOptions,
    ) -> Result<RunningBridge, StartError> {
        tracing::info!("starting bridge on plan {}", grant.plan_code());
        let tls_cfg = if opts.config.tls_enabled {
            opts.tls.clone()
        } else {
            None
        };
        let has_tls = tls_cfg.is_some();
        let config = opts.config.clone();
        let plan = tokio::task::spawn_blocking(move || plan_ports(&config, has_tls))
            .await
            .map_err(|e| StartError::Io(format!("port selection failed: {}", e)))??;
        let ports = plan.ports;
        let host = LOOPBACK_HOST;
        let jmap_https = opts.config.jmap_https_enabled && has_tls;
        let carddav_https = opts.config.carddav_https_enabled && has_tls;

        let RuntimeDeps {
            session,
            db,
            client,
            passwords,
        } = deps;

        let (stop_signal_tx, mut stop_signal_rx) = mpsc::unbounded_channel::<StopReason>();
        let mut handles: Vec<(Service, JoinHandle<()>)> = Vec::new();
        let broadcaster = crate::jmap::state::broadcaster();

        {
            let addr = format!("{}:{}", host, ports.imap);
            let (s, d, c, p, b, t) = (
                session.clone(),
                db.clone(),
                client.clone(),
                passwords.clone(),
                broadcaster.clone(),
                tls_cfg.clone(),
            );
            let fut = async move { crate::imap::server::run(&addr, s, d, c, p, b, t).await };
            handles.push((
                Service::Imap,
                spawn_listener(Service::Imap, Some(stop_signal_tx.clone()), fut),
            ));
        }

        if let (Some(cfg), true) = (tls_cfg.clone(), ports.imaps != 0) {
            let addr = format!("{}:{}", host, ports.imaps);
            let (s, d, c, p, b) = (
                session.clone(),
                db.clone(),
                client.clone(),
                passwords.clone(),
                broadcaster.clone(),
            );
            let fut = async move {
                crate::imap::server::run_implicit_tls(&addr, s, d, c, p, b, cfg).await
            };
            handles.push((Service::Imaps, spawn_listener(Service::Imaps, None, fut)));
        }

        {
            let addr = format!("{}:{}", host, ports.smtp);
            let (s, c, p, d, t) = (
                session.clone(),
                client.clone(),
                passwords.clone(),
                db.clone(),
                tls_cfg.clone(),
            );
            let fut = async move { crate::smtp::server::run(&addr, s, c, p, d, t).await };
            handles.push((
                Service::Smtp,
                spawn_listener(Service::Smtp, Some(stop_signal_tx.clone()), fut),
            ));
        }

        if let (Some(cfg), true) = (tls_cfg.clone(), ports.smtps != 0) {
            let addr = format!("{}:{}", host, ports.smtps);
            let (s, c, p, d) = (
                session.clone(),
                client.clone(),
                passwords.clone(),
                db.clone(),
            );
            let fut = async move {
                crate::smtp::server::run_implicit_tls(&addr, s, c, p, d, cfg).await
            };
            handles.push((Service::Smtps, spawn_listener(Service::Smtps, None, fut)));
        }

        if plan.jmap_enabled {
            let addr = format!("{}:{}", host, ports.jmap);
            let (s, d, c, p, b) = (
                session.clone(),
                db.clone(),
                client.clone(),
                passwords.clone(),
                broadcaster.clone(),
            );
            let t = if jmap_https { tls_cfg.clone() } else { None };
            let fut = async move { crate::jmap::server::run(&addr, s, d, c, p, b, t).await };
            handles.push((Service::Jmap, spawn_listener(Service::Jmap, None, fut)));
        }

        if plan.carddav_enabled {
            let addr = format!("{}:{}", host, ports.carddav);
            let (s, c, p) = (session.clone(), client.clone(), passwords.clone());
            let t = if carddav_https { tls_cfg.clone() } else { None };
            let fut = async move { crate::dav::server::run(&addr, s, c, p, t).await };
            handles.push((Service::Carddav, spawn_listener(Service::Carddav, None, fut)));
        }

        if ports.pop3 != 0 {
            let addr = format!("{}:{}", host, ports.pop3);
            let (s, d, c, p, t) = (
                session.clone(),
                db.clone(),
                client.clone(),
                passwords.clone(),
                tls_cfg.clone(),
            );
            let fut = async move { crate::pop3::server::run(&addr, s, d, c, p, t).await };
            handles.push((Service::Pop3, spawn_listener(Service::Pop3, None, fut)));
        }

        if let (Some(cfg), true) = (tls_cfg.clone(), ports.pop3s != 0) {
            let addr = format!("{}:{}", host, ports.pop3s);
            let (s, d, c, p) = (
                session.clone(),
                db.clone(),
                client.clone(),
                passwords.clone(),
            );
            let fut = async move {
                crate::pop3::server::run_implicit_tls(&addr, s, d, c, p, cfg).await
            };
            handles.push((Service::Pop3s, spawn_listener(Service::Pop3s, None, fut)));
        }

        let (sync_tx, sync_rx) = poller::sync_trigger_channel();
        {
            let (s, c, d, b) = (
                session.clone(),
                client.clone(),
                db.clone(),
                Some(broadcaster.clone()),
            );
            let tuning = opts.tuning.poll;
            let stop = stop_signal_tx.clone();
            handles.push((
                Service::Sync,
                tokio::spawn(async move {
                    if poller::run_poll_loop_tuned(s, c, d, b, sync_rx, tuning).await
                        == PollExit::AccessRevoked
                    {
                        let _ = stop.send(StopReason::AccessRevoked);
                    }
                }),
            ));
        }
        poller::set_global_sync_trigger(Some(sync_tx.clone()));

        {
            let gc_db = db.clone();
            let every = opts.tuning.blob_gc_interval;
            handles.push((
                Service::Gc,
                tokio::spawn(async move {
                    let mut tick = tokio::time::interval(every);
                    loop {
                        tick.tick().await;
                        match gc_db.jmap_blob_gc(24 * 3600) {
                            Ok(0) => {}
                            Ok(n) => tracing::debug!("jmap_blob GC removed {} expired blobs", n),
                            Err(e) => tracing::warn!("jmap_blob GC failed: {}", e),
                        }
                    }
                }),
            ));
        }

        let _ = db.outbox_reset_stale_sending(0);
        let (outbox_tx, outbox_rx) = crate::outbox::outbox_trigger_channel();
        {
            let (s, c, d) = (session.clone(), client.clone(), db.clone());
            handles.push((
                Service::Outbox,
                tokio::spawn(async move {
                    crate::outbox::run_outbox_loop(s, c, d, outbox_rx).await;
                }),
            ));
        }

        {
            let s = session.clone();
            let c = client.clone();
            let device_id = opts.device_id;
            let signing_key = opts.signing_key.clone();
            let profile = opts.profile;
            let tuning = opts.tuning;
            let stop = stop_signal_tx.clone();
            handles.push((
                Service::TokenRefresh,
                tokio::spawn(async move {
                    let mut consecutive_failures: u32 = 0;
                    loop {
                        let wait = if consecutive_failures == 0 {
                            tuning.token_refresh_interval
                        } else {
                            tuning.token_retry_interval
                        };
                        tokio::time::sleep(wait).await;
                        match crate::auth::session::refresh_access_token(
                            &s,
                            device_id,
                            &signing_key,
                            &c,
                        )
                        .await
                        {
                            Ok(()) => {
                                if consecutive_failures > 0 {
                                    tracing::info!("access token refresh recovered");
                                }
                                consecutive_failures = 0;
                            }
                            Err(e) => {
                                consecutive_failures = consecutive_failures.saturating_add(1);
                                tracing::warn!(
                                    "proactive token refresh failed (attempt {}): {}",
                                    consecutive_failures,
                                    e
                                );
                                if profile == ClientProfile::Cli
                                    && is_definitive_device_failure(&e)
                                {
                                    poller::emit_session_expired();
                                    let _ = stop.send(StopReason::DeviceRevoked);
                                    return;
                                }
                                if consecutive_failures == SESSION_EXPIRED_AFTER_FAILURES {
                                    poller::emit_session_expired();
                                }
                            }
                        }
                    }
                }),
            ));
        }
        drop(stop_signal_tx);

        let (stop_tx, stop_rx) = watch::channel(None);
        let inner = Arc::new(Inner {
            handles: StdMutex::new(handles),
            stop_tx,
            sync_trigger: sync_tx,
        });

        let weak: Weak<Inner> = Arc::downgrade(&inner);
        tokio::spawn(async move {
            if let Some(reason) = stop_signal_rx.recv().await {
                if let Some(inner) = weak.upgrade() {
                    inner.stop(reason);
                }
            }
        });

        tracing::info!(
            "bridge started - IMAP on {}:{}, SMTP on {}:{}, JMAP on {}:{} (enabled={}, tls={})",
            host,
            ports.imap,
            host,
            ports.smtp,
            host,
            ports.jmap,
            plan.jmap_enabled,
            has_tls,
        );

        Ok(RunningBridge {
            inner,
            ports,
            outbox_trigger: outbox_tx,
            stop_rx,
        })
    }
}
