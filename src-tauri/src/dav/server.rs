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
use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{ConnectInfo, DefaultBodyLimit, FromRef, Path, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use tokio::sync::RwLock;

use crate::api_client::ApiClient;
use crate::auth::app_passwords::AppPasswords;
use crate::auth::session::Session;
use crate::jmap::auth::{AuthedAccount, JmapAuth};

use super::store::{collection_ctag, is_safe_uid, ContactEntry, ContactsStore};
use super::xml::{escape_xml, parse_propfind, parse_report, PropRequest, ReportRequest};

const ROOT_PATH: &str = "/";
const PRINCIPAL_PATH: &str = "/principals/user/";
const HOME_PATH: &str = "/addressbooks/user/";
const BOOK_PATH: &str = "/addressbooks/user/contacts/";
const WELL_KNOWN_PATH: &str = "/.well-known/carddav";
const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_RESOURCE_SIZE: usize = 512 * 1024;
const NAMESPACES: &str =
    r#"xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav" xmlns:CS="http://calendarserver.org/ns/""#;

#[derive(Clone)]
pub struct DavState {
    pub store: Arc<ContactsStore>,
    pub auth: Arc<JmapAuth>,
    pub bind_port: u16,
    pub use_https: bool,
}

impl FromRef<DavState> for Arc<JmapAuth> {
    fn from_ref(state: &DavState) -> Self {
        state.auth.clone()
    }
}

pub async fn run(
    addr: &str,
    session: Arc<RwLock<Session>>,
    client: Arc<ApiClient>,
    passwords: Arc<AppPasswords>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
) -> Result<(), String> {
    let sock_addr: SocketAddr = addr
        .parse()
        .map_err(|e: std::net::AddrParseError| e.to_string())?;

    if let Some(cfg) = tls_config {
        let app = build_app(session, client, passwords, sock_addr.port(), true);
        tracing::info!("CardDAV server listening on https://{}", sock_addr);
        let rustls_cfg = axum_server::tls_rustls::RustlsConfig::from_config(cfg);
        return axum_server::bind_rustls(sock_addr, rustls_cfg)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .map_err(|e| e.to_string());
    }

    let listener = crate::port_picker::bind_loopback_listener(addr)
        .await
        .map_err(|e| format!("bind {} failed: {}", sock_addr, e))?;

    serve(listener, session, client, passwords).await
}

pub async fn serve(
    listener: tokio::net::TcpListener,
    session: Arc<RwLock<Session>>,
    client: Arc<ApiClient>,
    passwords: Arc<AppPasswords>,
) -> Result<(), String> {
    let sock_addr = listener.local_addr().map_err(|e| e.to_string())?;
    let app = build_app(session, client, passwords, sock_addr.port(), false);

    tracing::info!("CardDAV server listening on http://{}", sock_addr);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(|e| e.to_string())
}

pub fn build_app(
    session: Arc<RwLock<Session>>,
    client: Arc<ApiClient>,
    passwords: Arc<AppPasswords>,
    bind_port: u16,
    use_https: bool,
) -> Router {
    let auth = Arc::new(JmapAuth {
        passwords,
        session: session.clone(),
    });
    let store = Arc::new(ContactsStore::new(client, session));

    let state = DavState {
        store,
        auth,
        bind_port,
        use_https,
    };

    Router::new()
        .route(WELL_KNOWN_PATH, any(well_known))
        .route(ROOT_PATH, any(collection_handler))
        .route("/principals", any(collection_handler))
        .route("/principals/", any(collection_handler))
        .route("/principals/user", any(collection_handler))
        .route(PRINCIPAL_PATH, any(collection_handler))
        .route("/addressbooks", any(collection_handler))
        .route("/addressbooks/", any(collection_handler))
        .route("/addressbooks/user", any(collection_handler))
        .route(HOME_PATH, any(collection_handler))
        .route("/addressbooks/user/contacts", any(collection_handler))
        .route(BOOK_PATH, any(collection_handler))
        .route("/addressbooks/user/contacts/:name", any(card_handler))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(middleware::from_fn(move |req, next| {
            request_guard(req, next, bind_port, use_https)
        }))
        .layer(middleware::from_fn(loopback_only))
        .with_state(state)
}

async fn loopback_only(req: Request, next: Next) -> Response {
    match req.extensions().get::<ConnectInfo<SocketAddr>>().cloned() {
        Some(ConnectInfo(addr)) if addr.ip().is_loopback() => next.run(req).await,
        _ => (StatusCode::FORBIDDEN, "loopback only").into_response(),
    }
}

async fn request_guard(req: Request, next: Next, port: u16, use_https: bool) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let allowed_hosts = [
        format!("127.0.0.1:{}", port),
        format!("localhost:{}", port),
        format!("[::1]:{}", port),
    ];
    if !allowed_hosts.iter().any(|a| a.eq_ignore_ascii_case(host)) {
        return (StatusCode::FORBIDDEN, "bad host").into_response();
    }

    if let Some(origin) = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
    {
        let scheme = if use_https { "https" } else { "http" };
        let allowed_origins = [
            format!("{}://127.0.0.1:{}", scheme, port),
            format!("{}://localhost:{}", scheme, port),
            format!("{}://[::1]:{}", scheme, port),
        ];
        if !allowed_origins
            .iter()
            .any(|a| a.eq_ignore_ascii_case(origin))
        {
            return (StatusCode::FORBIDDEN, "bad origin").into_response();
        }
    }

    if let Some(site) = req
        .headers()
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
    {
        if !site.eq_ignore_ascii_case("same-origin") && !site.eq_ignore_ascii_case("none") {
            return (StatusCode::FORBIDDEN, "cross-site request blocked").into_response();
        }
    }

    let content_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_lowercase();

    let method = req.method().as_str().to_uppercase();
    let type_ok = match method.as_str() {
        "PUT" => matches!(content_type.as_str(), "text/vcard" | "text/x-vcard" | ""),
        "PROPFIND" | "REPORT" | "PROPPATCH" => {
            matches!(content_type.as_str(), "application/xml" | "text/xml" | "")
        }
        _ => true,
    };
    if !type_ok {
        return (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported content type",
        )
            .into_response();
    }

    next.run(req).await
}

fn dav_headers() -> [(header::HeaderName, HeaderValue); 2] {
    [
        (
            header::HeaderName::from_static("dav"),
            HeaderValue::from_static("1, 2, 3, addressbook"),
        ),
        (
            header::HeaderName::from_static("allow"),
            HeaderValue::from_static(
                "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, REPORT",
            ),
        ),
    ]
}

fn options_response() -> Response {
    (StatusCode::OK, dav_headers(), "").into_response()
}

fn multistatus(body: String) -> Response {
    (
        StatusCode::MULTI_STATUS,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/xml; charset=utf-8"),
        )],
        format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:multistatus {}>{}</D:multistatus>",
            NAMESPACES, body
        ),
    )
        .into_response()
}

fn depth_of(headers: &HeaderMap) -> String {
    headers
        .get("depth")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("0")
        .trim()
        .to_lowercase()
}

fn render_propstats(request: &PropRequest, available: &[(&str, String)]) -> String {
    let mut found = String::new();
    let mut missing = String::new();

    if request.propname {
        for (name, _) in available {
            found.push_str(&format!("<D:{}/>", name));
        }
    } else if request.allprop {
        for (_, xml) in available {
            found.push_str(xml);
        }
    } else {
        for name in &request.names {
            match available.iter().find(|(key, _)| key == name) {
                Some((_, xml)) => found.push_str(xml),
                None => missing.push_str(&format!("<D:{}/>", escape_xml(name))),
            }
        }
    }

    let mut out = String::new();
    if !found.is_empty() {
        out.push_str(&format!(
            "<D:propstat><D:prop>{}</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>",
            found
        ));
    }
    if !missing.is_empty() {
        out.push_str(&format!(
            "<D:propstat><D:prop>{}</D:prop><D:status>HTTP/1.1 404 Not Found</D:status></D:propstat>",
            missing
        ));
    }
    if out.is_empty() {
        out.push_str("<D:propstat><D:prop/><D:status>HTTP/1.1 200 OK</D:status></D:propstat>");
    }
    out
}

fn response_block(href: &str, propstats: String) -> String {
    format!(
        "<D:response><D:href>{}</D:href>{}</D:response>",
        escape_xml(href),
        propstats
    )
}

fn privilege_set() -> String {
    "<D:current-user-privilege-set><D:privilege><D:read/></D:privilege><D:privilege><D:write/></D:privilege><D:privilege><D:write-content/></D:privilege><D:privilege><D:write-properties/></D:privilege><D:privilege><D:bind/></D:privilege><D:privilege><D:unbind/></D:privilege></D:current-user-privilege-set>".to_string()
}

fn current_user_principal() -> String {
    format!(
        "<D:current-user-principal><D:href>{}</D:href></D:current-user-principal>",
        PRINCIPAL_PATH
    )
}

fn plain_collection_props(display_name: &str) -> Vec<(&'static str, String)> {
    vec![
        (
            "resourcetype",
            "<D:resourcetype><D:collection/></D:resourcetype>".to_string(),
        ),
        (
            "displayname",
            format!("<D:displayname>{}</D:displayname>", escape_xml(display_name)),
        ),
        ("current-user-principal", current_user_principal()),
        (
            "principal-url",
            format!(
                "<D:principal-URL><D:href>{}</D:href></D:principal-URL>",
                PRINCIPAL_PATH
            ),
        ),
        (
            "principal-collection-set",
            format!(
                "<D:principal-collection-set><D:href>{}</D:href></D:principal-collection-set>",
                PRINCIPAL_PATH
            ),
        ),
        (
            "addressbook-home-set",
            format!(
                "<C:addressbook-home-set><D:href>{}</D:href></C:addressbook-home-set>",
                HOME_PATH
            ),
        ),
        ("current-user-privilege-set", privilege_set()),
        (
            "supported-report-set",
            "<D:supported-report-set/>".to_string(),
        ),
    ]
}

fn principal_props(email: &str) -> Vec<(&'static str, String)> {
    let mut props = plain_collection_props(email);
    props[0] = (
        "resourcetype",
        "<D:resourcetype><D:principal/></D:resourcetype>".to_string(),
    );
    props.push((
        "email-address-set",
        format!(
            "<CS:email-address-set><CS:email-address>{}</CS:email-address></CS:email-address-set>",
            escape_xml(email)
        ),
    ));
    props
}

fn addressbook_props(ctag: &str) -> Vec<(&'static str, String)> {
    vec![
        (
            "resourcetype",
            "<D:resourcetype><D:collection/><C:addressbook/></D:resourcetype>".to_string(),
        ),
        (
            "displayname",
            "<D:displayname>Contacts</D:displayname>".to_string(),
        ),
        (
            "addressbook-description",
            "<C:addressbook-description>Aster contacts</C:addressbook-description>".to_string(),
        ),
        (
            "supported-address-data",
            "<C:supported-address-data><C:address-data-type content-type=\"text/vcard\" version=\"3.0\"/></C:supported-address-data>".to_string(),
        ),
        (
            "max-resource-size",
            format!("<C:max-resource-size>{}</C:max-resource-size>", MAX_RESOURCE_SIZE),
        ),
        ("getctag", format!("<CS:getctag>{}</CS:getctag>", escape_xml(ctag))),
        ("current-user-principal", current_user_principal()),
        ("current-user-privilege-set", privilege_set()),
        (
            "supported-report-set",
            "<D:supported-report-set><D:supported-report><D:report><C:addressbook-multiget/></D:report></D:supported-report><D:supported-report><D:report><C:addressbook-query/></D:report></D:supported-report></D:supported-report-set>".to_string(),
        ),
    ]
}

fn card_props(entry: &ContactEntry, include_data: bool) -> Vec<(&'static str, String)> {
    let mut props = vec![
        ("resourcetype", "<D:resourcetype/>".to_string()),
        (
            "getetag",
            format!("<D:getetag>{}</D:getetag>", escape_xml(&entry.etag)),
        ),
        (
            "getcontenttype",
            "<D:getcontenttype>text/vcard; charset=utf-8</D:getcontenttype>".to_string(),
        ),
        (
            "getcontentlength",
            format!(
                "<D:getcontentlength>{}</D:getcontentlength>",
                entry.vcard.len()
            ),
        ),
    ];
    if include_data {
        props.push((
            "address-data",
            format!(
                "<C:address-data>{}</C:address-data>",
                escape_xml(&entry.vcard)
            ),
        ));
    }
    props
}

fn card_href(uid: &str) -> String {
    format!("{}{}.vcf", BOOK_PATH, uid)
}

fn uid_from_href(href: &str) -> Option<String> {
    let path = href.split(['?', '#']).next().unwrap_or(href);
    let path = match path.find("://") {
        Some(index) => {
            let rest = &path[index + 3..];
            let start = rest.find('/')?;
            &rest[start..]
        }
        None => path,
    };
    let name = path.strip_prefix(BOOK_PATH)?;
    let uid = name.strip_suffix(".vcf").unwrap_or(name);
    is_safe_uid(uid).then(|| uid.to_string())
}

async fn well_known(req: Request) -> Response {
    if req.method().as_str().eq_ignore_ascii_case("OPTIONS") {
        return options_response();
    }
    (
        StatusCode::MOVED_PERMANENTLY,
        [(header::LOCATION, HeaderValue::from_static(ROOT_PATH))],
        "",
    )
        .into_response()
}

fn normalize_path(path: &str) -> String {
    if path.ends_with('/') {
        path.to_string()
    } else {
        format!("{}/", path)
    }
}

async fn collection_handler(
    _account: AuthedAccount,
    State(state): State<DavState>,
    req: Request,
) -> Response {
    let method = req.method().clone();
    let path = normalize_path(req.uri().path());

    if method == Method::OPTIONS {
        return options_response();
    }

    if method.as_str().eq_ignore_ascii_case("PROPFIND") {
        return propfind_collection(state, path, req).await;
    }

    if method.as_str().eq_ignore_ascii_case("REPORT") {
        if path != BOOK_PATH {
            return (StatusCode::FORBIDDEN, "reports are addressbook only").into_response();
        }
        return report_addressbook(state, req).await;
    }

    if method == Method::GET || method == Method::HEAD {
        return (StatusCode::METHOD_NOT_ALLOWED, dav_headers(), "").into_response();
    }

    (StatusCode::METHOD_NOT_ALLOWED, dav_headers(), "").into_response()
}

async fn read_body(req: Request) -> Result<String, Response> {
    let bytes = axum::body::to_bytes(req.into_body(), MAX_BODY_BYTES)
        .await
        .map_err(|_| (StatusCode::PAYLOAD_TOO_LARGE, "body too large").into_response())?;
    String::from_utf8(bytes.to_vec())
        .map_err(|_| (StatusCode::BAD_REQUEST, "body must be utf-8").into_response())
}

async fn propfind_collection(state: DavState, path: String, req: Request) -> Response {
    let depth = depth_of(req.headers());
    let body = match read_body(req).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let props = match parse_propfind(&body) {
        Ok(props) => props,
        Err(message) => return (StatusCode::BAD_REQUEST, message).into_response(),
    };

    let email = state.auth.session.read().await.email.clone();

    let mut out = String::new();

    match path.as_str() {
        PRINCIPAL_PATH => {
            out.push_str(&response_block(
                PRINCIPAL_PATH,
                render_propstats(&props, &principal_props(&email)),
            ));
        }
        BOOK_PATH => {
            let entries = match state.store.list().await {
                Ok(entries) => entries,
                Err(e) => return store_error(e),
            };
            out.push_str(&response_block(
                BOOK_PATH,
                render_propstats(&props, &addressbook_props(&collection_ctag(&entries))),
            ));
            if depth != "0" {
                for entry in &entries {
                    out.push_str(&response_block(
                        &card_href(&entry.uid),
                        render_propstats(&props, &card_props(entry, props.wants("address-data"))),
                    ));
                }
            }
        }
        HOME_PATH => {
            out.push_str(&response_block(
                HOME_PATH,
                render_propstats(&props, &plain_collection_props("Aster")),
            ));
            if depth != "0" {
                let entries = match state.store.list().await {
                    Ok(entries) => entries,
                    Err(e) => return store_error(e),
                };
                out.push_str(&response_block(
                    BOOK_PATH,
                    render_propstats(&props, &addressbook_props(&collection_ctag(&entries))),
                ));
            }
        }
        other => {
            out.push_str(&response_block(
                other,
                render_propstats(&props, &plain_collection_props("Aster")),
            ));
            if depth != "0" && other == ROOT_PATH {
                out.push_str(&response_block(
                    PRINCIPAL_PATH,
                    render_propstats(&props, &principal_props(&email)),
                ));
            }
        }
    }

    multistatus(out)
}

async fn report_addressbook(state: DavState, req: Request) -> Response {
    let body = match read_body(req).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let report = match parse_report(&body) {
        Ok(report) => report,
        Err(message) => return (StatusCode::BAD_REQUEST, message).into_response(),
    };

    let entries = match state.store.list().await {
        Ok(entries) => entries,
        Err(e) => return store_error(e),
    };

    match report {
        ReportRequest::Query { props } => {
            let mut out = String::new();
            for entry in &entries {
                out.push_str(&response_block(
                    &card_href(&entry.uid),
                    render_propstats(&props, &card_props(entry, props.wants("address-data"))),
                ));
            }
            multistatus(out)
        }
        ReportRequest::Multiget { props, hrefs } => {
            let mut out = String::new();
            for href in hrefs {
                let uid = uid_from_href(&href);
                let entry = uid
                    .as_ref()
                    .and_then(|uid| entries.iter().find(|e| &e.uid == uid));
                match entry {
                    Some(entry) => out.push_str(&response_block(
                        &card_href(&entry.uid),
                        render_propstats(&props, &card_props(entry, props.wants("address-data"))),
                    )),
                    None => out.push_str(&format!(
                        "<D:response><D:href>{}</D:href><D:status>HTTP/1.1 404 Not Found</D:status></D:response>",
                        escape_xml(&href)
                    )),
                }
            }
            multistatus(out)
        }
        ReportRequest::Unsupported => (
            StatusCode::FORBIDDEN,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/xml; charset=utf-8"),
            )],
            format!(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?><D:error {}><D:supported-report/></D:error>",
                NAMESPACES
            ),
        )
            .into_response(),
    }
}

fn store_error(error: crate::error::BridgeError) -> Response {
    tracing::warn!("carddav store error: {}", error);
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "contacts are temporarily unavailable",
    )
        .into_response()
}

fn if_match_values(headers: &HeaderMap, name: &str) -> Option<Vec<String>> {
    let raw = headers.get(name)?.to_str().ok()?;
    Some(
        raw.split(',')
            .map(|v| v.trim().trim_start_matches("W/").trim().to_string())
            .filter(|v| !v.is_empty())
            .collect(),
    )
}

async fn card_handler(
    _account: AuthedAccount,
    State(state): State<DavState>,
    Path(name): Path<String>,
    req: Request,
) -> Response {
    let method = req.method().clone();

    if method == Method::OPTIONS {
        return options_response();
    }

    let uid = name.strip_suffix(".vcf").unwrap_or(&name).to_string();
    if !is_safe_uid(&uid) {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }

    if method.as_str().eq_ignore_ascii_case("PROPFIND") {
        let body = match read_body(req).await {
            Ok(body) => body,
            Err(response) => return response,
        };
        let props = match parse_propfind(&body) {
            Ok(props) => props,
            Err(message) => return (StatusCode::BAD_REQUEST, message).into_response(),
        };
        return match state.store.get(&uid).await {
            Ok(Some(entry)) => multistatus(response_block(
                &card_href(&entry.uid),
                render_propstats(&props, &card_props(&entry, props.wants("address-data"))),
            )),
            Ok(None) => (StatusCode::NOT_FOUND, "not found").into_response(),
            Err(e) => store_error(e),
        };
    }

    if method == Method::GET || method == Method::HEAD {
        return match state.store.get(&uid).await {
            Ok(Some(entry)) => {
                let headers = [
                    (
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("text/vcard; charset=utf-8"),
                    ),
                    (
                        header::ETAG,
                        HeaderValue::from_str(&entry.etag)
                            .unwrap_or(HeaderValue::from_static("\"0\"")),
                    ),
                ];
                if method == Method::HEAD {
                    (StatusCode::OK, headers, Body::empty()).into_response()
                } else {
                    (StatusCode::OK, headers, entry.vcard).into_response()
                }
            }
            Ok(None) => (StatusCode::NOT_FOUND, "not found").into_response(),
            Err(e) => store_error(e),
        };
    }

    if method == Method::PUT {
        let headers = req.headers().clone();
        let body = match read_body(req).await {
            Ok(body) => body,
            Err(response) => return response,
        };

        let existing = match state.store.get(&uid).await {
            Ok(existing) => existing,
            Err(e) => return store_error(e),
        };

        if let Some(values) = if_match_values(&headers, "if-none-match") {
            if values.iter().any(|v| v == "*") && existing.is_some() {
                return (StatusCode::PRECONDITION_FAILED, "already exists").into_response();
            }
        }
        if let Some(values) = if_match_values(&headers, "if-match") {
            let matches = match &existing {
                Some(entry) => values.iter().any(|v| v == "*" || v == &entry.etag),
                None => false,
            };
            if !matches {
                return (StatusCode::PRECONDITION_FAILED, "etag mismatch").into_response();
            }
        }

        if !body.contains("BEGIN:VCARD") {
            return (StatusCode::BAD_REQUEST, "not a vcard").into_response();
        }

        return match state.store.put(&uid, &body).await {
            Ok((entry, created)) => {
                let status = if created {
                    StatusCode::CREATED
                } else {
                    StatusCode::NO_CONTENT
                };
                (
                    status,
                    [(
                        header::ETAG,
                        HeaderValue::from_str(&entry.etag)
                            .unwrap_or(HeaderValue::from_static("\"0\"")),
                    )],
                    "",
                )
                    .into_response()
            }
            Err(e) => store_error(e),
        };
    }

    if method == Method::DELETE {
        let headers = req.headers().clone();
        if let Some(values) = if_match_values(&headers, "if-match") {
            match state.store.get(&uid).await {
                Ok(Some(entry)) => {
                    if !values.iter().any(|v| v == "*" || v == &entry.etag) {
                        return (StatusCode::PRECONDITION_FAILED, "etag mismatch").into_response();
                    }
                }
                Ok(None) => return (StatusCode::NOT_FOUND, "not found").into_response(),
                Err(e) => return store_error(e),
            }
        }
        return match state.store.delete(&uid).await {
            Ok(true) => (StatusCode::NO_CONTENT, "").into_response(),
            Ok(false) => (StatusCode::NOT_FOUND, "not found").into_response(),
            Err(e) => store_error(e),
        };
    }

    (StatusCode::METHOD_NOT_ALLOWED, dav_headers(), "").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn props(names: &[&str]) -> PropRequest {
        PropRequest {
            names: names.iter().map(|n| n.to_string()).collect(),
            allprop: false,
            propname: false,
        }
    }

    fn sample_entry() -> ContactEntry {
        ContactEntry {
            uid: "abc-123".to_string(),
            contact_id: "server-id".to_string(),
            etag: "\"deadbeef\"".to_string(),
            vcard: "BEGIN:VCARD\r\nFN:A & B\r\nEND:VCARD\r\n".to_string(),
        }
    }

    #[test]
    fn requested_props_that_exist_come_back_as_200() {
        let rendered = render_propstats(&props(&["getetag"]), &card_props(&sample_entry(), false));

        assert!(rendered.contains("<D:getetag>&quot;deadbeef&quot;</D:getetag>"));
        assert!(rendered.contains("HTTP/1.1 200 OK"));
        assert!(!rendered.contains("404"));
    }

    #[test]
    fn requested_props_that_do_not_exist_come_back_as_404() {
        let rendered = render_propstats(
            &props(&["getetag", "made-up-prop"]),
            &card_props(&sample_entry(), false),
        );

        assert!(rendered.contains("<D:made-up-prop/>"));
        assert!(rendered.contains("HTTP/1.1 404 Not Found"));
        assert!(rendered.contains("HTTP/1.1 200 OK"));
    }

    #[test]
    fn address_data_is_escaped_in_the_multistatus_body() {
        let rendered = render_propstats(&props(&["address-data"]), &card_props(&sample_entry(), true));

        assert!(rendered.contains("FN:A &amp; B"));
        assert!(!rendered.contains("FN:A & B"));
    }

    #[test]
    fn allprop_returns_every_available_property() {
        let request = PropRequest {
            names: Vec::new(),
            allprop: true,
            propname: false,
        };
        let rendered = render_propstats(&request, &addressbook_props("\"ctag\""));

        assert!(rendered.contains("<C:addressbook/>"));
        assert!(rendered.contains("<CS:getctag>&quot;ctag&quot;</CS:getctag>"));
        assert!(!rendered.contains("404"));
    }

    #[test]
    fn propname_returns_names_without_values() {
        let request = PropRequest {
            names: Vec::new(),
            allprop: false,
            propname: true,
        };
        let rendered = render_propstats(&request, &card_props(&sample_entry(), false));

        assert!(rendered.contains("<D:getetag/>"));
        assert!(!rendered.contains("deadbeef"));
    }

    #[test]
    fn a_missing_prop_name_cannot_inject_markup() {
        let rendered = render_propstats(&props(&["<script>"]), &card_props(&sample_entry(), false));

        assert!(rendered.contains("&lt;script&gt;"));
        assert!(!rendered.contains("<script>"));
    }

    #[test]
    fn hrefs_resolve_to_uids_and_reject_traversal() {
        assert_eq!(
            uid_from_href("/addressbooks/user/contacts/abc-123.vcf").as_deref(),
            Some("abc-123")
        );
        assert_eq!(
            uid_from_href("/addressbooks/user/contacts/abc-123").as_deref(),
            Some("abc-123")
        );
        assert!(uid_from_href("/addressbooks/user/contacts/../../secret").is_none());
        assert!(uid_from_href("/addressbooks/user/contacts/").is_none());
    }

    #[test]
    fn card_hrefs_live_under_the_addressbook() {
        assert_eq!(card_href("abc-123"), "/addressbooks/user/contacts/abc-123.vcf");
    }

    #[test]
    fn paths_are_normalized_with_a_trailing_slash() {
        assert_eq!(normalize_path("/principals/user"), PRINCIPAL_PATH);
        assert_eq!(normalize_path(PRINCIPAL_PATH), PRINCIPAL_PATH);
    }

    #[test]
    fn principal_props_expose_the_addressbook_home_set() {
        let rendered = render_propstats(
            &props(&["addressbook-home-set", "resourcetype"]),
            &principal_props("user@aster.test"),
        );

        assert!(rendered.contains("<C:addressbook-home-set><D:href>/addressbooks/user/</D:href>"));
        assert!(rendered.contains("<D:principal/>"));
    }

    #[test]
    fn depth_defaults_to_zero_when_absent() {
        let mut headers = HeaderMap::new();
        assert_eq!(depth_of(&headers), "0");
        headers.insert("depth", HeaderValue::from_static("1"));
        assert_eq!(depth_of(&headers), "1");
    }

    #[test]
    fn conditional_headers_are_split_and_normalized() {
        let mut headers = HeaderMap::new();
        headers.insert("if-match", HeaderValue::from_static("W/\"a\", \"b\""));

        assert_eq!(
            if_match_values(&headers, "if-match").unwrap(),
            vec!["\"a\"".to_string(), "\"b\"".to_string()]
        );
        assert!(if_match_values(&headers, "if-none-match").is_none());
    }
}

#[cfg(test)]
mod e2e_tests {
    use super::*;
    use crate::auth::session::Session;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use serde_json::{json, Value};
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;
    use std::time::Duration;
    use uuid::Uuid;

    type Rows = Arc<StdMutex<HashMap<String, Value>>>;

    async fn stub_backend() -> (String, Rows) {
        let rows: Rows = Arc::new(StdMutex::new(HashMap::new()));

        let list_rows = rows.clone();
        let create_rows = rows.clone();
        let update_rows = rows.clone();
        let delete_rows = rows.clone();

        let app = Router::new()
            .route(
                "/contacts/v1/",
                axum::routing::get(move || {
                    let rows = list_rows.clone();
                    async move {
                        let items: Vec<Value> =
                            rows.lock().unwrap().values().cloned().collect();
                        axum::Json(json!({
                            "items": items,
                            "next_cursor": Value::Null,
                            "has_more": false,
                        }))
                    }
                })
                .post(move |axum::Json(body): axum::Json<Value>| {
                    let rows = create_rows.clone();
                    async move {
                        let id = Uuid::new_v4().to_string();
                        let mut record = body.clone();
                        let object = record.as_object_mut().unwrap();
                        object.insert("id".to_string(), Value::from(id.clone()));
                        object.insert("created_at".to_string(), Value::from("2026-08-21T00:00:00Z"));
                        object.insert("updated_at".to_string(), Value::from("2026-08-21T00:00:00Z"));
                        rows.lock().unwrap().insert(id.clone(), record);
                        axum::Json(json!({ "id": id }))
                    }
                }),
            )
            .route(
                "/contacts/v1/:id",
                axum::routing::put(
                    move |Path(id): Path<String>, axum::Json(body): axum::Json<Value>| {
                        let rows = update_rows.clone();
                        async move {
                            let mut guard = rows.lock().unwrap();
                            match guard.get_mut(&id) {
                                Some(existing) => {
                                    let target = existing.as_object_mut().unwrap();
                                    for (key, value) in body.as_object().unwrap() {
                                        target.insert(key.clone(), value.clone());
                                    }
                                    StatusCode::OK
                                }
                                None => StatusCode::NOT_FOUND,
                            }
                        }
                    },
                )
                .delete(move |Path(id): Path<String>| {
                    let rows = delete_rows.clone();
                    async move {
                        match rows.lock().unwrap().remove(&id) {
                            Some(_) => StatusCode::OK,
                            None => StatusCode::NOT_FOUND,
                        }
                    }
                }),
            );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (base, rows)
    }

    async fn start_dav() -> (String, String, Rows, tempfile::TempDir) {
        let (api_base, rows) = stub_backend().await;

        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(crate::db::Database::open_with_key(dir.path(), &[9u8; 32]).unwrap());
        let passwords = Arc::new(AppPasswords::new(db.clone()));
        let _ = passwords.store("test", "abcd-efgh-ijkl-mnop").unwrap();

        let session = Arc::new(RwLock::new(Session {
            data_kek: Some(zeroize::Zeroizing::new(STANDARD.encode([5u8; 32]))),
            user_id: Uuid::new_v4(),
            username: "tester".to_string(),
            email: "tester@aster.test".to_string(),
            access_token: zeroize::Zeroizing::new("stub".to_string()),
            vault_passphrase: Vec::new(),
            identity_key: None,
            ratchet_identity_public: None,
            ratchet_keys: Vec::new(),
            inbound_keys: Vec::new(),
            send_identities: Vec::new(),
        }));

        let client = Arc::new(ApiClient::new_with_base_url(&api_base));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let auth = format!(
            "Basic {}",
            STANDARD.encode(b"tester@aster.test:abcd-efgh-ijkl-mnop")
        );

        let (s, c, p) = (session.clone(), client.clone(), passwords.clone());
        tokio::spawn(async move {
            let _ = serve(listener, s, c, p).await;
        });

        for _ in 0..200 {
            if reqwest::Client::new()
                .get(format!("{}/.well-known/carddav", base))
                .send()
                .await
                .is_ok()
            {
                return (base, auth, rows, dir);
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("carddav test server did not become ready")
    }

    fn dav_request(
        method: &str,
        url: &str,
        auth: &str,
    ) -> reqwest::RequestBuilder {
        reqwest::Client::new()
            .request(reqwest::Method::from_bytes(method.as_bytes()).unwrap(), url)
            .header(reqwest::header::AUTHORIZATION, auth)
    }

    const CARD: &str = "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:ada-1\r\nFN:Ada Lovelace\r\nN:Lovelace;Ada;;;\r\nEMAIL;TYPE=INTERNET,WORK:ada@example.com\r\nTEL;TYPE=CELL:+15550000\r\nEND:VCARD\r\n";

    #[tokio::test]
    async fn well_known_redirects_to_the_service_root() {
        let (base, _auth, _rows, _dir) = start_dav().await;
        let response = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap()
            .get(format!("{}/.well-known/carddav", base))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 301);
        assert_eq!(response.headers()["location"], "/");
    }

    #[tokio::test]
    async fn propfind_requires_authentication() {
        let (base, _auth, _rows, _dir) = start_dav().await;
        let response = reqwest::Client::new()
            .request(reqwest::Method::from_bytes(b"PROPFIND").unwrap(), format!("{}/", base))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 401);
    }

    #[tokio::test]
    async fn a_bad_app_password_is_rejected() {
        let (base, _auth, _rows, _dir) = start_dav().await;
        let bad = format!(
            "Basic {}",
            STANDARD.encode(b"tester@aster.test:wrong-wrong-wrong")
        );
        let response = dav_request("PROPFIND", &format!("{}/", base), &bad)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 401);
    }

    #[tokio::test]
    async fn options_advertises_the_addressbook_capability() {
        let (base, auth, _rows, _dir) = start_dav().await;
        let response = dav_request("OPTIONS", &format!("{}/", base), &auth)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
        assert!(response.headers()["dav"]
            .to_str()
            .unwrap()
            .contains("addressbook"));
    }

    #[tokio::test]
    async fn discovery_walks_root_to_principal_to_addressbook() {
        let (base, auth, _rows, _dir) = start_dav().await;

        let root = dav_request("PROPFIND", &format!("{}/", base), &auth)
            .header("depth", "0")
            .header("content-type", "application/xml")
            .body(r#"<D:propfind xmlns:D="DAV:"><D:prop><D:current-user-principal/></D:prop></D:propfind>"#)
            .send()
            .await
            .unwrap();
        assert_eq!(root.status(), 207);
        let body = root.text().await.unwrap();
        assert!(body.contains("<D:href>/principals/user/</D:href>"));

        let principal = dav_request("PROPFIND", &format!("{}/principals/user/", base), &auth)
            .header("depth", "0")
            .header("content-type", "application/xml")
            .body(r#"<D:propfind xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav"><D:prop><C:addressbook-home-set/></D:prop></D:propfind>"#)
            .send()
            .await
            .unwrap();
        assert_eq!(principal.status(), 207);
        let body = principal.text().await.unwrap();
        assert!(body.contains("<D:href>/addressbooks/user/</D:href>"));

        let home = dav_request("PROPFIND", &format!("{}/addressbooks/user/", base), &auth)
            .header("depth", "1")
            .header("content-type", "application/xml")
            .body(r#"<D:propfind xmlns:D="DAV:"><D:prop><D:resourcetype/><D:displayname/></D:prop></D:propfind>"#)
            .send()
            .await
            .unwrap();
        assert_eq!(home.status(), 207);
        let body = home.text().await.unwrap();
        assert!(body.contains("<D:href>/addressbooks/user/contacts/</D:href>"));
        assert!(body.contains("<C:addressbook/>"));
    }

    #[tokio::test]
    async fn a_card_survives_put_get_and_delete() {
        let (base, auth, rows, _dir) = start_dav().await;
        let card_url = format!("{}/addressbooks/user/contacts/ada-1.vcf", base);

        let created = dav_request("PUT", &card_url, &auth)
            .header("content-type", "text/vcard")
            .body(CARD)
            .send()
            .await
            .unwrap();
        assert_eq!(created.status(), 201);
        assert!(created.headers().contains_key("etag"));
        assert_eq!(rows.lock().unwrap().len(), 1);

        let stored = rows.lock().unwrap().values().next().unwrap().clone();
        assert!(stored["encrypted_data"].as_str().unwrap().len() > 0);
        let blob = format!("{}", stored);
        assert!(!blob.contains("Lovelace"));
        assert!(!blob.contains("ada@example.com"));

        let fetched = dav_request("GET", &card_url, &auth).send().await.unwrap();
        assert_eq!(fetched.status(), 200);
        assert_eq!(
            fetched.headers()["content-type"],
            "text/vcard; charset=utf-8"
        );
        let text = fetched.text().await.unwrap();
        assert!(text.contains("UID:ada-1\r\n"));
        assert!(text.contains("FN:Ada Lovelace\r\n"));
        assert!(text.contains("ada@example.com"));
        assert!(text.contains("+15550000"));

        let updated = dav_request("PUT", &card_url, &auth)
            .header("content-type", "text/vcard")
            .body(CARD.replace("Ada Lovelace", "Ada B Lovelace"))
            .send()
            .await
            .unwrap();
        assert_eq!(updated.status(), 204);
        assert_eq!(rows.lock().unwrap().len(), 1);

        let removed = dav_request("DELETE", &card_url, &auth).send().await.unwrap();
        assert_eq!(removed.status(), 204);
        assert!(rows.lock().unwrap().is_empty());

        let gone = dav_request("GET", &card_url, &auth).send().await.unwrap();
        assert_eq!(gone.status(), 404);
    }

    #[tokio::test]
    async fn the_addressbook_lists_cards_and_the_ctag_tracks_changes() {
        let (base, auth, _rows, _dir) = start_dav().await;
        let book_url = format!("{}/addressbooks/user/contacts/", base);

        let ctag_body = r#"<D:propfind xmlns:D="DAV:" xmlns:CS="http://calendarserver.org/ns/"><D:prop><CS:getctag/></D:prop></D:propfind>"#;
        let before = dav_request("PROPFIND", &book_url, &auth)
            .header("depth", "0")
            .header("content-type", "application/xml")
            .body(ctag_body)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();

        dav_request("PUT", &format!("{}ada-1.vcf", book_url), &auth)
            .header("content-type", "text/vcard")
            .body(CARD)
            .send()
            .await
            .unwrap();

        let listing = dav_request("PROPFIND", &book_url, &auth)
            .header("depth", "1")
            .header("content-type", "application/xml")
            .body(r#"<D:propfind xmlns:D="DAV:"><D:prop><D:getetag/></D:prop></D:propfind>"#)
            .send()
            .await
            .unwrap();
        assert_eq!(listing.status(), 207);
        let body = listing.text().await.unwrap();
        assert!(body.contains("<D:href>/addressbooks/user/contacts/ada-1.vcf</D:href>"));

        let after = dav_request("PROPFIND", &book_url, &auth)
            .header("depth", "0")
            .header("content-type", "application/xml")
            .body(ctag_body)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();

        assert_ne!(before, after);
    }

    #[tokio::test]
    async fn multiget_returns_the_requested_cards_with_data() {
        let (base, auth, _rows, _dir) = start_dav().await;
        let book_url = format!("{}/addressbooks/user/contacts/", base);

        dav_request("PUT", &format!("{}ada-1.vcf", book_url), &auth)
            .header("content-type", "text/vcard")
            .body(CARD)
            .send()
            .await
            .unwrap();

        let report = dav_request("REPORT", &book_url, &auth)
            .header("depth", "1")
            .header("content-type", "application/xml")
            .body(
                r#"<C:addressbook-multiget xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">
                    <D:prop><D:getetag/><C:address-data/></D:prop>
                    <D:href>/addressbooks/user/contacts/ada-1.vcf</D:href>
                    <D:href>/addressbooks/user/contacts/missing.vcf</D:href>
                  </C:addressbook-multiget>"#,
            )
            .send()
            .await
            .unwrap();

        assert_eq!(report.status(), 207);
        let body = report.text().await.unwrap();
        assert!(body.contains("BEGIN:VCARD"));
        assert!(body.contains("FN:Ada Lovelace"));
        assert!(body.contains("404 Not Found"));
    }

    #[tokio::test]
    async fn addressbook_query_returns_every_card() {
        let (base, auth, _rows, _dir) = start_dav().await;
        let book_url = format!("{}/addressbooks/user/contacts/", base);

        dav_request("PUT", &format!("{}ada-1.vcf", book_url), &auth)
            .header("content-type", "text/vcard")
            .body(CARD)
            .send()
            .await
            .unwrap();

        let report = dav_request("REPORT", &book_url, &auth)
            .header("depth", "1")
            .header("content-type", "application/xml")
            .body(
                r#"<C:addressbook-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">
                    <D:prop><D:getetag/><C:address-data/></D:prop><C:filter/>
                  </C:addressbook-query>"#,
            )
            .send()
            .await
            .unwrap();

        assert_eq!(report.status(), 207);
        assert!(report.text().await.unwrap().contains("FN:Ada Lovelace"));
    }

    #[tokio::test]
    async fn conditional_writes_are_honored() {
        let (base, auth, _rows, _dir) = start_dav().await;
        let card_url = format!("{}/addressbooks/user/contacts/ada-1.vcf", base);

        let created = dav_request("PUT", &card_url, &auth)
            .header("content-type", "text/vcard")
            .header("if-none-match", "*")
            .body(CARD)
            .send()
            .await
            .unwrap();
        assert_eq!(created.status(), 201);
        let etag = created.headers()["etag"].to_str().unwrap().to_string();

        let duplicate = dav_request("PUT", &card_url, &auth)
            .header("content-type", "text/vcard")
            .header("if-none-match", "*")
            .body(CARD)
            .send()
            .await
            .unwrap();
        assert_eq!(duplicate.status(), 412);

        let stale = dav_request("PUT", &card_url, &auth)
            .header("content-type", "text/vcard")
            .header("if-match", "\"stale\"")
            .body(CARD)
            .send()
            .await
            .unwrap();
        assert_eq!(stale.status(), 412);

        let fresh = dav_request("PUT", &card_url, &auth)
            .header("content-type", "text/vcard")
            .header("if-match", &etag)
            .body(CARD.replace("Ada Lovelace", "Ada B Lovelace"))
            .send()
            .await
            .unwrap();
        assert_eq!(fresh.status(), 204);
    }

    #[tokio::test]
    async fn sync_collection_is_answered_as_an_unsupported_report() {
        let (base, auth, _rows, _dir) = start_dav().await;

        let response = dav_request(
            "REPORT",
            &format!("{}/addressbooks/user/contacts/", base),
            &auth,
        )
        .header("content-type", "application/xml")
        .body(r#"<D:sync-collection xmlns:D="DAV:"><D:prop><D:getetag/></D:prop></D:sync-collection>"#)
        .send()
        .await
        .unwrap();

        assert_eq!(response.status(), 403);
        assert!(response.text().await.unwrap().contains("supported-report"));
    }

    #[tokio::test]
    async fn a_cross_site_request_is_blocked() {
        let (base, auth, _rows, _dir) = start_dav().await;

        let response = dav_request("PROPFIND", &format!("{}/", base), &auth)
            .header("sec-fetch-site", "cross-site")
            .header("content-type", "application/xml")
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 403);
    }

    #[tokio::test]
    async fn a_foreign_host_header_is_blocked() {
        let (base, auth, _rows, _dir) = start_dav().await;

        let response = dav_request("PROPFIND", &format!("{}/", base), &auth)
            .header(reqwest::header::HOST, "evil.example")
            .header("content-type", "application/xml")
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 403);
    }

    #[tokio::test]
    async fn a_doctype_in_a_propfind_body_is_rejected() {
        let (base, auth, _rows, _dir) = start_dav().await;

        let response = dav_request("PROPFIND", &format!("{}/", base), &auth)
            .header("content-type", "application/xml")
            .body(
                r#"<!DOCTYPE propfind [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><D:propfind xmlns:D="DAV:"><D:prop><D:displayname>&xxe;</D:displayname></D:prop></D:propfind>"#,
            )
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 400);
    }

    #[tokio::test]
    async fn a_traversal_resource_name_is_not_found() {
        let (base, auth, _rows, _dir) = start_dav().await;

        let response = dav_request(
            "GET",
            &format!("{}/addressbooks/user/contacts/%2e%2e%2fsecret", base),
            &auth,
        )
        .send()
        .await
        .unwrap();

        assert!(response.status() == 404 || response.status() == 400);
    }
}
