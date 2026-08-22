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
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};

pub const HEARTBEAT_LINE: &[u8] = b"* OK still working\r\n";

const PRODUCTION_INTERVAL_SECS: u64 = 15;

pub fn heartbeat_interval() -> Duration {
    if cfg!(test) {
        Duration::from_millis(150)
    } else {
        Duration::from_secs(PRODUCTION_INTERVAL_SECS)
    }
}

enum PumpMessage {
    Bytes(Vec<u8>),
    Flush(oneshot::Sender<std::io::Result<()>>),
    Wake,
}

pub struct HeartbeatWriter<W> {
    tx: Option<mpsc::UnboundedSender<PumpMessage>>,
    armed: Arc<AtomicBool>,
    command_active: Arc<AtomicBool>,
    pending_flush: Option<oneshot::Receiver<std::io::Result<()>>>,
    pump: Option<tokio::task::JoinHandle<W>>,
}

impl<W> HeartbeatWriter<W>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    pub fn new(inner: W, every: Duration) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let armed = Arc::new(AtomicBool::new(false));
        let pump = tokio::spawn(pump(inner, rx, armed.clone(), every));
        Self {
            tx: Some(tx),
            armed,
            command_active: Arc::new(AtomicBool::new(false)),
            pending_flush: None,
            pump: Some(pump),
        }
    }

    pub fn arm(&self) {
        self.command_active.store(true, Ordering::SeqCst);
        self.armed.store(true, Ordering::SeqCst);
        if let Some(tx) = self.tx.as_ref() {
            let _ = tx.send(PumpMessage::Wake);
        }
    }

    pub fn disarm(&self) {
        self.command_active.store(false, Ordering::SeqCst);
        self.armed.store(false, Ordering::SeqCst);
    }

    pub async fn reclaim(mut self) -> std::io::Result<W> {
        self.tx = None;
        match self.pump.take() {
            Some(handle) => handle
                .await
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string())),
            None => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "the connection writer was already reclaimed",
            )),
        }
    }

    fn send(&self, message: PumpMessage) -> std::io::Result<()> {
        match self.tx.as_ref() {
            Some(tx) => tx.send(message).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "the connection is closed")
            }),
            None => Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "the connection is closed",
            )),
        }
    }
}

impl<W> AsyncWrite for HeartbeatWriter<W>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        this.armed.store(false, Ordering::SeqCst);
        match this.send(PumpMessage::Bytes(buf.to_vec())) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.pending_flush.is_none() {
            let (ack_tx, ack_rx) = oneshot::channel();
            if let Err(e) = this.send(PumpMessage::Flush(ack_tx)) {
                return Poll::Ready(Err(e));
            }
            this.pending_flush = Some(ack_rx);
        }
        let receiver = this.pending_flush.as_mut().expect("flush was just queued");
        match Pin::new(receiver).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                this.pending_flush = None;
                match result {
                    Ok(inner) => {
                        if inner.is_ok() && this.command_active.load(Ordering::SeqCst) {
                            this.armed.store(true, Ordering::SeqCst);
                        }
                        Poll::Ready(inner)
                    }
                    Err(_) => Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "the connection is closed",
                    ))),
                }
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.poll_flush(cx)
    }
}

async fn pump<W>(
    mut inner: W,
    mut rx: mpsc::UnboundedReceiver<PumpMessage>,
    armed: Arc<AtomicBool>,
    every: Duration,
) -> W
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    loop {
        tokio::select! {
            message = rx.recv() => match message {
                Some(PumpMessage::Bytes(bytes)) => {
                    if inner.write_all(&bytes).await.is_err() {
                        break;
                    }
                }
                Some(PumpMessage::Flush(ack)) => {
                    let result = inner.flush().await;
                    let failed = result.is_err();
                    let _ = ack.send(result);
                    if failed {
                        break;
                    }
                }
                Some(PumpMessage::Wake) => {}
                None => break,
            },
            _ = tokio::time::sleep(every) => {
                if !armed.load(Ordering::SeqCst) {
                    continue;
                }
                tracing::debug!("IMAP command is still running, sending a keepalive so the client does not time out");
                if inner.write_all(HEARTBEAT_LINE).await.is_err() {
                    break;
                }
                if inner.flush().await.is_err() {
                    break;
                }
            }
        }
    }
    inner
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[derive(Clone, Default)]
    struct Recorder {
        bytes: Arc<std::sync::Mutex<Vec<u8>>>,
    }

    impl AsyncWrite for Recorder {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.bytes.lock().unwrap().extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct BrokenSocket;

    impl AsyncWrite for BrokenSocket {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "gone",
            )))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "gone",
            )))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn written(recorder: &Recorder) -> String {
        String::from_utf8_lossy(&recorder.bytes.lock().unwrap()).to_string()
    }

    #[tokio::test]
    async fn an_armed_connection_keeps_speaking_while_a_command_runs() {
        let recorder = Recorder::default();
        let writer = HeartbeatWriter::new(recorder.clone(), Duration::from_millis(60));
        writer.arm();

        tokio::time::sleep(Duration::from_millis(400)).await;

        let seen = written(&recorder);
        let beats = seen.matches("* OK still working").count();
        assert!(
            beats >= 3,
            "expected repeated keepalives while armed, saw {}: {:?}",
            beats,
            seen
        );
    }

    #[tokio::test]
    async fn a_disarmed_connection_stays_silent() {
        let recorder = Recorder::default();
        let _writer = HeartbeatWriter::new(recorder.clone(), Duration::from_millis(50));

        tokio::time::sleep(Duration::from_millis(400)).await;

        assert_eq!(written(&recorder), "", "an idle connection must send nothing");
    }

    #[tokio::test]
    async fn a_keepalive_is_never_injected_into_a_response_already_in_flight() {
        let recorder = Recorder::default();
        let mut writer = HeartbeatWriter::new(recorder.clone(), Duration::from_millis(50));
        writer.arm();

        writer
            .write_all(b"* 1 FETCH (BODY[] {11}\r\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        writer.write_all(b"hello world").await.unwrap();
        writer.write_all(b")\r\n").await.unwrap();
        writer.flush().await.unwrap();

        let seen = written(&recorder);
        assert!(
            !seen.contains("still working"),
            "a keepalive landed inside a literal and corrupted the response: {:?}",
            seen
        );
        assert_eq!(seen, "* 1 FETCH (BODY[] {11}\r\nhello world)\r\n");
    }

    #[tokio::test]
    async fn writes_reach_the_socket_in_order() {
        let recorder = Recorder::default();
        let mut writer = HeartbeatWriter::new(recorder.clone(), Duration::from_secs(30));

        for n in 0..50 {
            writer
                .write_all(format!("* {} EXISTS\r\n", n).as_bytes())
                .await
                .unwrap();
        }
        writer.flush().await.unwrap();

        let seen = written(&recorder);
        let expected: String = (0..50).map(|n| format!("* {} EXISTS\r\n", n)).collect();
        assert_eq!(seen, expected);
    }

    #[tokio::test]
    async fn a_dead_socket_surfaces_as_a_write_error_so_the_session_ends() {
        let mut writer = HeartbeatWriter::new(BrokenSocket, Duration::from_secs(30));

        let _ = writer.write_all(b"* OK hello\r\n").await;
        let _ = writer.flush().await;

        let mut failed = false;
        for _ in 0..50 {
            if writer.write_all(b"* OK hello\r\n").await.is_err() {
                failed = true;
                break;
            }
            if writer.flush().await.is_err() {
                failed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            failed,
            "writes to a dead socket kept succeeding, so the session would never end"
        );
    }

    #[tokio::test]
    async fn the_socket_can_be_reclaimed_for_a_tls_upgrade() {
        let recorder = Recorder::default();
        let mut writer = HeartbeatWriter::new(recorder.clone(), Duration::from_secs(30));
        writer.write_all(b"a1 OK Begin TLS negotiation now\r\n").await.unwrap();
        writer.flush().await.unwrap();

        let reclaimed = writer.reclaim().await.unwrap();

        assert_eq!(written(&recorder), "a1 OK Begin TLS negotiation now\r\n");
        assert_eq!(
            Arc::as_ptr(&reclaimed.bytes),
            Arc::as_ptr(&recorder.bytes),
            "reclaim must hand back the same socket the pump was holding"
        );
    }

    #[tokio::test]
    async fn the_production_interval_leaves_room_under_a_sixty_second_client_timeout() {
        assert!(
            Duration::from_secs(PRODUCTION_INTERVAL_SECS) * 3 < Duration::from_secs(60),
            "a client that gives up after 60 seconds must see at least three keepalives first"
        );
    }

    #[tokio::test]
    async fn an_append_keeps_the_client_informed_after_the_continuation_is_sent() {
        let recorder = Recorder::default();
        let mut writer = HeartbeatWriter::new(recorder.clone(), Duration::from_millis(50));
        writer.arm();
        writer
            .write_all(b"+ Ready for literal data\r\n")
            .await
            .unwrap();
        writer.flush().await.unwrap();

        tokio::time::sleep(Duration::from_millis(400)).await;

        let seen = written(&recorder);
        let beats = seen.matches("still working").count();
        assert!(
            beats >= 3,
            "the connection went silent after the continuation, which is what makes a mail client abandon a mailbox import: {:?}",
            seen
        );
    }

    #[test]
    fn a_heartbeat_still_reaches_the_client_while_every_worker_is_blocked_on_the_database() {
        let workers = 2;
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(workers)
            .enable_all()
            .build()
            .unwrap();
        let recorder = Recorder::default();
        let observed = recorder.clone();
        let gate = Arc::new(std::sync::Mutex::new(()));

        rt.spawn({
            let recorder = recorder.clone();
            async move {
                let mut writer = HeartbeatWriter::new(recorder, Duration::from_millis(50));
                writer.arm();
                writer
                    .write_all(b"+ Ready for literal data\r\n")
                    .await
                    .unwrap();
                writer.flush().await.unwrap();
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        });
        std::thread::sleep(Duration::from_millis(120));

        for _ in 0..workers {
            let held = Arc::clone(&gate);
            rt.spawn(async move {
                crate::db::without_starving_the_runtime(|| {
                    let _guard = held.lock().unwrap();
                    std::thread::sleep(Duration::from_secs(3));
                });
            });
        }

        std::thread::sleep(Duration::from_millis(1500));
        let seen = written(&observed);
        let beats = seen.matches("still working").count();
        drop(rt);
        assert!(
            beats >= 2,
            "the connection went silent for over a second while the database held every worker, which is exactly what makes a mail client report that the server stopped responding: {:?}",
            seen
        );
    }
}
