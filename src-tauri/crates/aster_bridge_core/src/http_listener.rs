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
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::extract::ConnectInfo;
use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::OwnedSemaphorePermit;
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_rustls::TlsAcceptor;

use crate::conn_limit::{try_acquire_connection, PreAuthClock, Protocol, PRE_AUTH_IDLE_TIMEOUT};
use crate::shutdown::{ConnectionShutdown, HTTP_CLOSE_GRACE};

const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);
const NOT_STALLED: u64 = u64::MAX;

pub async fn serve(
    listener: TcpListener,
    protocol: Protocol,
    app: Router,
    tls_config: Option<Arc<rustls::ServerConfig>>,
) -> Result<(), String> {
    accept_loop(listener, app, tls_config, move || try_acquire_connection(protocol)).await
}

async fn accept_loop<A>(
    listener: TcpListener,
    app: Router,
    tls_config: Option<Arc<rustls::ServerConfig>>,
    acquire: A,
) -> Result<(), String>
where
    A: Fn() -> Option<OwnedSemaphorePermit>,
{
    let shutdown = crate::shutdown::current();
    let acceptor = tls_config.map(TlsAcceptor::from);
    let mut connections = JoinSet::new();
    loop {
        while connections.try_join_next().is_some() {}
        let accepted = tokio::select! {
            _ = shutdown.clone().closed() => break,
            accepted = listener.accept() => accepted,
        };
        let (stream, peer) = match accepted {
            Ok(pair) => pair,
            Err(e) => {
                tracing::debug!("HTTP accept failed: {}", e);
                tokio::time::sleep(ACCEPT_RETRY_DELAY).await;
                continue;
            }
        };
        let Some(permit) = acquire() else {
            tracing::debug!("HTTP connection limit reached, refusing {}", peer);
            drop(stream);
            continue;
        };
        let _ = stream.set_nodelay(true);
        let (app, acceptor, scope) = (app.clone(), acceptor.clone(), shutdown.clone());
        connections.spawn(shutdown.clone().scope(async move {
            let _permit = permit;
            serve_connection(stream, peer, app, acceptor, scope).await;
        }));
    }
    drop(listener);
    while connections.join_next().await.is_some() {}
    Ok(())
}

pub(crate) async fn serve_connection<I>(
    io: I,
    peer: SocketAddr,
    app: Router,
    acceptor: Option<TlsAcceptor>,
    shutdown: ConnectionShutdown,
) where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let clock = PreAuthClock::start();
    let activity = Arc::new(Activity::new());
    let io = Tracked {
        inner: io,
        activity: activity.clone(),
    };
    let session = async {
        match acceptor {
            Some(acceptor) => {
                if let Ok(stream) = acceptor.accept(io).await {
                    serve_http(stream, peer, app, clock.clone(), shutdown).await;
                }
            }
            None => serve_http(io, peer, app, clock.clone(), shutdown).await,
        }
    };
    let watched = async {
        tokio::select! {
            _ = session => {}
            _ = idle_watch(&clock, &activity) => {}
        }
    };
    let _ = clock.guard(watched).await;
}

async fn serve_http<I>(
    io: I,
    peer: SocketAddr,
    app: Router,
    clock: PreAuthClock,
    shutdown: ConnectionShutdown,
) where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = hyper::service::service_fn(move |mut request: hyper::Request<hyper::body::Incoming>| {
        request.extensions_mut().insert(ConnectInfo(peer));
        request.extensions_mut().insert(clock.clone());
        let mut router = app.clone();
        async move { tower_service::Service::call(&mut router, request).await }
    });
    let mut builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(PRE_AUTH_IDLE_TIMEOUT);
    builder.http2().timer(TokioTimer::new());
    let connection = builder.serve_connection_with_upgrades(TokioIo::new(io), service);
    tokio::pin!(connection);
    tokio::select! {
        _ = connection.as_mut() => {}
        _ = shutdown.closed() => {
            connection.as_mut().graceful_shutdown();
            let _ = tokio::time::timeout(HTTP_CLOSE_GRACE, connection.as_mut()).await;
        }
    }
}

async fn idle_watch(clock: &PreAuthClock, activity: &Activity) {
    loop {
        if clock.is_signed_in() {
            std::future::pending::<()>().await;
        }
        let wake = activity.idle_deadline();
        if Instant::now() >= wake {
            return;
        }
        tokio::time::sleep_until(wake).await;
    }
}

struct Activity {
    base: Instant,
    last: AtomicU64,
    stalled_since: AtomicU64,
}

impl Activity {
    fn new() -> Self {
        Self {
            base: Instant::now(),
            last: AtomicU64::new(0),
            stalled_since: AtomicU64::new(NOT_STALLED),
        }
    }

    fn now(&self) -> u64 {
        u64::try_from(self.base.elapsed().as_millis()).unwrap_or(NOT_STALLED - 1)
    }

    fn touch(&self) {
        self.last.store(self.now(), Ordering::SeqCst);
    }

    fn write_progressed(&self) {
        self.stalled_since.store(NOT_STALLED, Ordering::SeqCst);
        self.touch();
    }

    fn write_blocked(&self) {
        let now = self.now();
        let _ = self.stalled_since.compare_exchange(
            NOT_STALLED,
            now,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
    }

    fn idle_deadline(&self) -> Instant {
        let last = self.last.load(Ordering::SeqCst);
        let stalled = self.stalled_since.load(Ordering::SeqCst);
        let from = if stalled == NOT_STALLED { last } else { last.min(stalled) };
        self.base + Duration::from_millis(from) + PRE_AUTH_IDLE_TIMEOUT
    }
}

struct Tracked<I> {
    inner: I,
    activity: Arc<Activity>,
}

impl<I: AsyncRead + Unpin> AsyncRead for Tracked<I> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            self.activity.touch();
        }
        result
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for Tracked<I> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, data);
        self.note_write(&result);
        result
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        self.note_write(&result);
        result
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let result = Pin::new(&mut self.inner).poll_flush(cx);
        if result.is_pending() {
            self.activity.write_blocked();
        }
        result
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<I> Tracked<I> {
    fn note_write(&self, result: &Poll<io::Result<usize>>) {
        match result {
            Poll::Ready(Ok(written)) if *written > 0 => self.activity.write_progressed(),
            Poll::Pending => self.activity.write_blocked(),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn_limit::test_support::{connect, flood_without_reading, read_until_closed};
    use crate::conn_limit::{PRE_AUTH_DEADLINE, PRE_AUTH_GRACE};
    use axum::routing::get;
    use axum::Extension;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn peer() -> SocketAddr {
        "127.0.0.1:40000".parse().unwrap()
    }

    fn test_app() -> Router {
        Router::new()
            .route("/", get(|| async { "hello" }))
            .route(
                "/sign-in",
                get(|Extension(clock): Extension<PreAuthClock>| async move {
                    clock.mark_signed_in();
                    "signed in"
                }),
            )
            .route(
                "/sign-in-and-wait",
                get(|Extension(clock): Extension<PreAuthClock>| async move {
                    clock.mark_signed_in();
                    tokio::time::sleep(PRE_AUTH_DEADLINE * 2).await;
                    "done"
                }),
            )
            .route(
                "/wait",
                get(|| async {
                    tokio::time::sleep(PRE_AUTH_DEADLINE * 2).await;
                    "done"
                }),
            )
            .route(
                "/peer",
                get(|ConnectInfo(addr): ConnectInfo<SocketAddr>| async move { addr.to_string() }),
            )
    }

    fn serve_test_app(io: tokio::io::DuplexStream) -> impl std::future::Future<Output = ()> + Send {
        serve_connection(io, peer(), test_app(), None, ConnectionShutdown::never())
    }

    async fn read_response(reader: &mut tokio::io::ReadHalf<tokio::io::DuplexStream>) -> String {
        let mut out = Vec::new();
        let mut chunk = [0u8; 1024];
        while !String::from_utf8_lossy(&out).contains("\r\n\r\n") {
            let n = reader.read(&mut chunk).await.unwrap();
            assert!(n > 0, "the connection closed before a response arrived");
            out.extend_from_slice(&chunk[..n]);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
        String::from_utf8_lossy(&out).into_owned()
    }

    #[tokio::test(start_paused = true)]
    async fn a_client_that_never_sends_is_closed_after_the_idle_timeout() {
        let started = Instant::now();
        let (mut reader, _writer) = connect(serve_test_app);
        let (_, closed) = read_until_closed(&mut reader, PRE_AUTH_IDLE_TIMEOUT * 2).await;
        assert!(closed, "a silent client must be dropped");
        assert!(started.elapsed() >= PRE_AUTH_IDLE_TIMEOUT);
        assert!(started.elapsed() < PRE_AUTH_IDLE_TIMEOUT + Duration::from_secs(2));
    }

    #[tokio::test(start_paused = true)]
    async fn a_client_that_never_reads_is_closed_after_the_idle_timeout() {
        let started = Instant::now();
        let (finished, _reader) = flood_without_reading(
            serve_test_app,
            b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
            PRE_AUTH_IDLE_TIMEOUT * 2,
        )
        .await;
        assert!(finished, "a client that never reads must not hold the connection");
        assert!(started.elapsed() >= PRE_AUTH_IDLE_TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn a_header_trickle_is_cut_before_the_pre_auth_deadline() {
        let started = Instant::now();
        let (mut reader, mut writer) = connect(serve_test_app);
        let trickle = tokio::spawn(async move {
            writer.write_all(b"GET / HTTP/1.1\r\n").await.ok();
            loop {
                tokio::time::sleep(PRE_AUTH_IDLE_TIMEOUT - Duration::from_secs(5)).await;
                if writer.write_all(b"X-Slow: 1\r\n").await.is_err() {
                    break;
                }
            }
        });
        let (_, closed) =
            read_until_closed(&mut reader, PRE_AUTH_DEADLINE + PRE_AUTH_GRACE).await;
        trickle.abort();
        assert!(closed, "a header trickle must be cut");
        assert!(started.elapsed() <= PRE_AUTH_IDLE_TIMEOUT + Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn a_request_is_answered_and_sees_the_peer_address() {
        let (mut reader, mut writer) = connect(serve_test_app);
        writer
            .write_all(b"GET /peer HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let response = read_response(&mut reader).await;
        assert!(response.starts_with("HTTP/1.1 200"), "{}", response);
        assert!(response.contains("127.0.0.1:40000"), "{}", response);
    }

    #[tokio::test(start_paused = true)]
    async fn a_signed_in_request_may_outlast_the_pre_auth_limits() {
        let (mut reader, mut writer) = connect(serve_test_app);
        writer
            .write_all(b"GET /sign-in-and-wait HTTP/1.1
Host: localhost

")
            .await
            .unwrap();
        let response = read_response(&mut reader).await;
        assert!(response.starts_with("HTTP/1.1 200"), "{}", response);
    }

    #[tokio::test(start_paused = true)]
    async fn a_request_that_never_signs_in_is_cut_at_the_idle_timeout() {
        let started = Instant::now();
        let (mut reader, mut writer) = connect(serve_test_app);
        writer
            .write_all(b"GET /wait HTTP/1.1
Host: localhost

")
            .await
            .unwrap();
        let (out, closed) = read_until_closed(&mut reader, PRE_AUTH_DEADLINE * 3).await;
        assert!(closed);
        assert!(out.is_empty(), "{}", out);
        assert!(started.elapsed() < PRE_AUTH_IDLE_TIMEOUT + Duration::from_secs(2));
    }

    #[tokio::test]
    async fn connections_past_the_limit_are_refused() {
        let pool = Arc::new(tokio::sync::Semaphore::new(1));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acquire_pool = pool.clone();
        let server = tokio::spawn(accept_loop(listener, test_app(), None, move || {
            acquire_pool.clone().try_acquire_owned().ok()
        }));

        let mut first = tokio::net::TcpStream::connect(addr).await.unwrap();
        first
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut buf = [0u8; 256];
        let n = first.read(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"));

        let mut second = tokio::net::TcpStream::connect(addr).await.unwrap();
        let _ = second
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await;
        let refused = tokio::time::timeout(Duration::from_secs(10), second.read(&mut buf))
            .await
            .expect("the refused connection must be closed");
        assert!(matches!(refused, Ok(0) | Err(_)), "a connection past the limit was served");

        drop(first);
        let mut third = None;
        for _ in 0..100 {
            if pool.available_permits() == 1 {
                third = Some(tokio::net::TcpStream::connect(addr).await.unwrap());
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let mut third = third.expect("the first connection never released its slot");
        third
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let n = third.read(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"));
        server.abort();
    }

    #[tokio::test]
    async fn closing_connections_stops_the_listener() {
        let (trigger, shutdown) = crate::shutdown::channel();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(shutdown.scope(async move {
            serve(listener, Protocol::Jmap, test_app(), None).await
        }));
        let mut open = tokio::net::TcpStream::connect(addr).await.unwrap();
        open.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut buf = [0u8; 256];
        let _ = open.read(&mut buf).await.unwrap();
        trigger.close_connections();
        let finished = tokio::time::timeout(HTTP_CLOSE_GRACE + Duration::from_secs(5), server)
            .await
            .expect("the listener must stop after sign-out");
        assert!(finished.unwrap().is_ok());
    }
}
