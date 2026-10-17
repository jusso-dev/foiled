//! The accept loop every TCP emulator shares: a session cap, clean shutdown
//! and health reporting.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};

use crate::{BoxFuture, EmulatorError, Health};

/// Most concurrent sessions per decoy. Further connections are closed at
/// once, as an overloaded server would.
pub(crate) const MAX_SESSIONS: usize = 128;

/// One connection's worth of protocol handling.
pub(crate) trait Session: Send + Sync + 'static {
    fn run(
        self: Arc<Self>,
        stream: TcpStream,
        peer: SocketAddr,
        local: SocketAddr,
        session_no: u64,
    ) -> impl Future<Output = ()> + Send;
}

#[derive(Default)]
pub(crate) struct Server {
    stop_tx: Option<watch::Sender<bool>>,
    task: Option<JoinHandle<()>>,
    sessions: Arc<AtomicUsize>,
    stopped: bool,
}

impl Server {
    pub(crate) fn start<S: Session>(
        &mut self,
        listener: TcpListener,
        session: Arc<S>,
    ) -> Result<(), EmulatorError> {
        if self.task.is_some() || self.stopped {
            return Err(EmulatorError::AlreadyStarted);
        }
        let handle = tokio::runtime::Handle::try_current().map_err(|_| EmulatorError::NoRuntime)?;
        let (tx, rx) = watch::channel(false);
        let sessions = self.sessions.clone();
        self.task = Some(handle.spawn(accept_loop(listener, session, rx, sessions)));
        self.stop_tx = Some(tx);
        Ok(())
    }

    pub(crate) fn stop(&mut self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            if let Some(tx) = self.stop_tx.take() {
                let _ = tx.send(true);
            }
            if let Some(task) = self.task.take() {
                let _ = task.await;
                self.stopped = true;
            }
        })
    }

    pub(crate) fn health(&self) -> Health {
        match &self.task {
            None if self.stopped => Health::Stopped,
            None => Health::NotStarted,
            Some(t) if t.is_finished() => Health::Failed("accept loop exited".into()),
            Some(_) => Health::Serving {
                sessions: self.sessions.load(Ordering::Relaxed),
            },
        }
    }
}

async fn accept_loop<S: Session>(
    listener: TcpListener,
    session: Arc<S>,
    mut stop: watch::Receiver<bool>,
    sessions: Arc<AtomicUsize>,
) {
    let mut set = JoinSet::new();
    let mut n: u64 = 0;
    loop {
        tokio::select! {
            biased;
            _ = stop.changed() => break,
            Some(_) = set.join_next(), if !set.is_empty() => {
                sessions.store(set.len(), Ordering::Relaxed);
            }
            accepted = listener.accept() => match accepted {
                Ok((stream, peer)) => {
                    let Ok(local) = stream.local_addr() else { continue };
                    if set.len() >= MAX_SESSIONS {
                        drop(stream);
                        continue;
                    }
                    let _ = stream.set_nodelay(true);
                    n += 1;
                    set.spawn(session.clone().run(stream, peer, local, n));
                    sessions.store(set.len(), Ordering::Relaxed);
                }
                // Accept errors (EMFILE, ECONNABORTED) are transient. Back off
                // briefly rather than spin.
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
    }
    drop(listener);
    set.shutdown().await;
    sessions.store(0, Ordering::Relaxed);
}
