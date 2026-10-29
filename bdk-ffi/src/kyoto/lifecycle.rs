use super::{
    polling::{Polling, PollingWorker},
    tokio, CbfError, Node,
};
use std::future::Future;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tokio::sync::{oneshot, watch};

#[derive(Debug)]
struct RunState {
    node: Option<Node>,
    thread: Option<JoinHandle<()>>,
    started: bool,
    worker: Option<PollingWorker>,
    lease_deadline: Option<Instant>,
}

/// Owns the native thread until it has actually exited, including runtime teardown.
#[derive(Debug)]
pub(super) struct NodeLifecycle {
    state: Mutex<RunState>,
    completed: Condvar,
    stop: watch::Sender<bool>,
    lease_ttl: Option<Duration>,
    renewed: watch::Sender<Option<Instant>>,
    polling: Option<Arc<Polling>>,
}

impl NodeLifecycle {
    #[cfg(test)]
    pub(super) fn new(node: Option<Node>) -> Self {
        Self::with_polling(node, None, None, None)
    }

    pub(super) fn with_polling(
        node: Option<Node>,
        lease_ttl: Option<Duration>,
        worker: Option<PollingWorker>,
        polling: Option<Arc<Polling>>,
    ) -> Self {
        let (stop, _) = watch::channel(false);
        let (renewed, _) = watch::channel(None);
        Self {
            state: Mutex::new(RunState {
                node,
                thread: None,
                started: false,
                worker,
                lease_deadline: None,
            }),
            completed: Condvar::new(),
            stop,
            lease_ttl,
            renewed,
            polling,
        }
    }

    pub(super) fn run(self: &Arc<Self>) {
        let mut state = self.state.lock().unwrap();
        let Some(node) = state.node.take() else {
            return;
        };
        let worker = state.worker.take();
        let polling = self.polling.clone();
        let lifecycle = self.clone();
        self.spawn_locked(&mut state, async move {
            if let Some(worker) = worker {
                tokio::select! {
                    result = node.run() => {
                        if let (Err(error), Some(polling)) = (result, polling) {
                            polling.error(error.to_string());
                        }
                    },
                    _ = worker.run() => {},
                }
            } else {
                let _ = node.run().await;
            }
            lifecycle.request_stop();
        });
    }

    fn spawn_locked<F>(self: &Arc<Self>, state: &mut RunState, task: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        if state.started {
            return;
        }
        state.started = true;
        if let Some(ttl) = self.lease_ttl {
            let deadline = Instant::now()
                .checked_add(ttl)
                .expect("validated lease TTL fits Instant");
            state.lease_deadline = Some(deadline);
            self.renewed.send_replace(Some(deadline));
        }
        let lifecycle = Arc::clone(self);
        let mut stop = self.stop.subscribe();
        let owner = self.clone();
        state.thread = std::thread::Builder::new()
            .name("bdk-cbf".into())
            .spawn(move || {
                struct Completion(Arc<NodeLifecycle>);
                impl Drop for Completion {
                    fn drop(&mut self) {
                        self.0.stop.send_replace(true);
                        self.0.completed.notify_all();
                    }
                }
                let _completion = Completion(lifecycle.clone());
                if let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    runtime.block_on(async move {
                        tokio::select! {
                            biased;
                            _ = stop.wait_for(|requested| *requested) => {},
                            _ = owner.wait_for_lease_expiry() => {},
                            _ = task => {},
                        }
                    });
                } else if let Some(polling) = &lifecycle.polling {
                    polling.error("failed to create native node runtime");
                }
            })
            .map_err(|error| {
                self.stop.send_replace(true);
                if let Some(polling) = &self.polling {
                    polling.error(format!("failed to start native node thread: {error}"));
                }
            })
            .ok();
    }

    pub(super) fn request_stop(&self) {
        self.stop.send_replace(true);
        let mut state = self.state.lock().unwrap();
        if !state.started {
            // A shutdown before run must also close the native channels immediately.
            state.node.take();
            state.worker.take();
        }
        self.completed.notify_all();
    }

    pub(super) fn stop_requested(&self) -> bool {
        *self.stop.borrow()
    }

    pub(super) fn renew_lease(&self) -> Result<(), CbfError> {
        let ttl = self
            .lease_ttl
            .ok_or_else(|| CbfError::InvalidConfiguration {
                reason: "this node has no owner lease".into(),
            })?;
        let mut state = self.state.lock().unwrap();
        if self.stop_requested()
            || !state.started
            || state
                .thread
                .as_ref()
                .is_none_or(|thread| thread.is_finished())
        {
            return Err(CbfError::NodeStopped);
        }
        let now = Instant::now();
        if state.lease_deadline.is_some_and(|deadline| now >= deadline) {
            self.stop.send_replace(true);
            if let Some(polling) = &self.polling {
                polling.error("owner lease expired");
            }
            return Err(CbfError::NodeStopped);
        }
        let deadline = now
            .checked_add(ttl)
            .expect("validated lease TTL fits Instant");
        state.lease_deadline = Some(deadline);
        self.renewed.send_replace(Some(deadline));
        Ok(())
    }

    async fn wait_for_lease_expiry(&self) {
        let mut renewed = self.renewed.subscribe();
        loop {
            let deadline = *renewed.borrow_and_update();
            let Some(deadline) = deadline else {
                std::future::pending::<()>().await;
                return;
            };
            tokio::select! {
                _ = tokio::time::sleep_until(deadline.into()) => {
                    // Serialize with renewal: an already-expired owner cannot revive the node.
                    let state = self.state.lock().unwrap();
                    if state.lease_deadline.is_some_and(|current| Instant::now() >= current) {
                        self.stop.send_replace(true);
                        if let Some(polling) = &self.polling { polling.error("owner lease expired"); }
                        return;
                    }
                },
                _ = renewed.changed() => {},
            }
        }
    }

    #[cfg(test)]
    pub(super) fn spawn_for_test<F>(self: &Arc<Self>, task: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.spawn_locked(&mut self.state.lock().unwrap(), task);
    }

    pub(super) fn is_terminated(&self) -> bool {
        self.wait(Duration::ZERO)
    }

    fn wait(&self, timeout: Duration) -> bool {
        let started = Instant::now();
        let mut state = self.state.lock().unwrap();
        loop {
            match state.thread.as_ref() {
                Some(thread) if thread.is_finished() => {
                    let _ = state.thread.take().unwrap().join();
                    return true;
                }
                None if state.started || (self.stop_requested() && state.node.is_none()) => {
                    return true
                }
                _ => {}
            }
            let remaining = timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                return false;
            }
            // Completion is signalled immediately before the thread exits. Polling also covers
            // that small gap without ever acknowledging a thread that has not exited.
            let (next, _) = self
                .completed
                .wait_timeout(state, remaining.min(Duration::from_millis(10)))
                .unwrap();
            state = next;
        }
    }

    pub(super) async fn await_termination(self: Arc<Self>, timeout: Duration) -> bool {
        // UniFFI polls this future without a Tokio runtime. The waiter therefore uses an OS
        // deadline and a runtime-independent oneshot, rather than tokio::time or spawn_blocking.
        let (send, receive) = oneshot::channel();
        let _ = std::thread::Builder::new()
            .name("bdk-cbf-join".into())
            .spawn(move || {
                let _ = send.send(self.wait(timeout));
            });
        receive.await.unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn executor() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn an_unrenewed_owner_lease_terminates_pending_setup() {
        let lifecycle = leased_lifecycle(Duration::from_millis(40));
        let (entered, ready) = std::sync::mpsc::channel();
        lifecycle.spawn_locked(&mut lifecycle.state.lock().unwrap(), async move {
            entered.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        ready.recv_timeout(Duration::from_secs(1)).unwrap();
        let stopped = executor().block_on(
            lifecycle
                .clone()
                .await_termination(Duration::from_millis(500)),
        );
        lifecycle.request_stop();
        assert!(executor().block_on(lifecycle.await_termination(Duration::from_secs(1))));
        assert!(
            stopped,
            "a dead owner must not leave native setup running beyond its lease"
        );
    }

    fn leased_lifecycle(ttl: Duration) -> Arc<NodeLifecycle> {
        Arc::new(NodeLifecycle::with_polling(None, Some(ttl), None, None))
    }

    #[test]
    fn renewal_keeps_the_native_task_alive_but_never_revives_an_expired_owner() {
        let lifecycle = leased_lifecycle(Duration::from_millis(120));
        lifecycle.spawn_locked(&mut lifecycle.state.lock().unwrap(), std::future::pending());
        for _ in 0..5 {
            std::thread::sleep(Duration::from_millis(40));
            lifecycle.renew_lease().unwrap();
            assert!(!lifecycle.is_terminated());
        }
        assert!(executor().block_on(lifecycle.clone().await_termination(Duration::from_secs(1))));
        assert!(matches!(
            lifecycle.renew_lease(),
            Err(CbfError::NodeStopped)
        ));
    }

    #[test]
    fn expired_deadline_cannot_be_renewed_before_the_runtime_polls_its_timer() {
        let lifecycle = leased_lifecycle(Duration::from_millis(40));
        let (entered, ready) = std::sync::mpsc::channel();
        let (release, receive) = std::sync::mpsc::channel();
        lifecycle.spawn_locked(&mut lifecycle.state.lock().unwrap(), async move {
            entered.send(()).unwrap();
            receive.recv_timeout(Duration::from_secs(1)).unwrap();
        });
        ready.recv_timeout(Duration::from_secs(1)).unwrap();
        std::thread::sleep(Duration::from_millis(60));
        assert!(matches!(
            lifecycle.renew_lease(),
            Err(CbfError::NodeStopped)
        ));
        release.send(()).unwrap();
        assert!(executor().block_on(lifecycle.await_termination(Duration::from_secs(1))));
    }

    #[test]
    fn shutdown_interrupts_pending_peer_setup() {
        let lifecycle = Arc::new(NodeLifecycle::new(None));
        let (entered, ready) = std::sync::mpsc::channel();
        let (release, receive) = oneshot::channel();
        lifecycle.spawn_locked(&mut lifecycle.state.lock().unwrap(), async move {
            entered.send(()).unwrap();
            let _ = receive.await;
        });
        ready.recv_timeout(Duration::from_secs(1)).unwrap();
        lifecycle.request_stop();
        let stopped = executor().block_on(
            lifecycle
                .clone()
                .await_termination(Duration::from_millis(300)),
        );
        let _ = release.send(());
        assert!(executor().block_on(lifecycle.await_termination(Duration::from_secs(1))));
        assert!(
            stopped,
            "shutdown must interrupt setup before any peer responds"
        );
    }

    #[test]
    fn shutdown_before_run_does_not_poll_setup() {
        let lifecycle = Arc::new(NodeLifecycle::new(None));
        let polled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observe = polled.clone();
        lifecycle.request_stop();
        lifecycle.spawn_locked(&mut lifecycle.state.lock().unwrap(), async move {
            observe.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        assert!(executor().block_on(lifecycle.await_termination(Duration::from_secs(1))));
        assert!(
            !polled.load(std::sync::atomic::Ordering::SeqCst),
            "shutdown before run must prevent setup"
        );
    }

    fn components() -> super::super::CbfComponents {
        use crate::{
            bitcoin::NetworkKind, descriptor::Descriptor, store::Persister, wallet::Wallet,
        };
        let descriptors: serde_json::Value =
            serde_json::from_str(include_str!("public-descriptors.json")).unwrap();
        let wallet = Wallet::new(
            Arc::new(
                Descriptor::new(
                    descriptors["external"].as_str().unwrap().into(),
                    NetworkKind::Main,
                )
                .unwrap(),
            ),
            Arc::new(
                Descriptor::new(
                    descriptors["internal"].as_str().unwrap().into(),
                    NetworkKind::Main,
                )
                .unwrap(),
            ),
            super::super::Network::Bitcoin,
            Arc::new(Persister::new_in_memory().unwrap()),
            25,
        )
        .unwrap();
        super::super::CbfBuilder::new()
            .only_configured_peers()
            .build(&wallet)
    }

    #[test]
    fn dropping_the_consumer_interrupts_pending_peer_setup() {
        let components = components();
        let lifecycle = components.node.lifecycle.clone();
        let (entered, ready) = std::sync::mpsc::channel();
        let (release, receive) = oneshot::channel();
        {
            let mut state = lifecycle.state.lock().unwrap();
            state.node.take();
            lifecycle.spawn_locked(&mut state, async move {
                entered.send(()).unwrap();
                let _ = receive.await;
            });
        }
        ready.recv_timeout(Duration::from_secs(1)).unwrap();
        drop(components.client);
        let stopped = executor().block_on(
            lifecycle
                .clone()
                .await_termination(Duration::from_millis(300)),
        );
        let _ = release.send(());
        assert!(executor().block_on(lifecycle.await_termination(Duration::from_secs(1))));
        assert!(
            stopped,
            "dropping the update consumer must stop setup without a peer response"
        );
    }

    #[test]
    fn termination_is_not_acknowledged_until_runtime_teardown_finishes() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let lifecycle = Arc::new(NodeLifecycle::new(None));
        let (entered, ready) = std::sync::mpsc::channel();
        let (release, receive) = std::sync::mpsc::channel();
        let peer_dropped = Arc::new(AtomicBool::new(false));
        let observe = peer_dropped.clone();
        lifecycle.spawn_locked(&mut lifecycle.state.lock().unwrap(), async move {
            struct PeerDrop(Arc<AtomicBool>);
            impl Drop for PeerDrop {
                fn drop(&mut self) {
                    self.0.store(true, Ordering::SeqCst);
                }
            }
            let peer = PeerDrop(observe);
            tokio::spawn(async move {
                let _peer = peer;
                std::future::pending::<()>().await;
            });
            // Models an OS resolver already executing on Tokio's blocking pool. It cannot
            // be aborted by dropping the outer node future.
            tokio::task::spawn_blocking(move || {
                entered.send(()).unwrap();
                let _ = receive.recv();
            });
            std::future::pending::<()>().await;
        });
        ready.recv_timeout(Duration::from_secs(1)).unwrap();
        lifecycle.request_stop();
        let stopped = executor().block_on(
            lifecycle
                .clone()
                .await_termination(Duration::from_millis(30)),
        );
        release.send(()).unwrap();
        assert!(executor().block_on(lifecycle.await_termination(Duration::from_secs(1))));
        assert!(
            !stopped,
            "a live blocking resolver must prevent termination acknowledgement"
        );
        assert!(
            peer_dropped.load(Ordering::SeqCst),
            "runtime teardown must drop child peer tasks"
        );
    }

    #[test]
    fn public_shutdown_before_run_closes_channels_and_acknowledges_termination() {
        let components = components();
        let runtime = executor();
        assert!(!runtime.block_on(components.node.await_termination(0)));
        components.client.shutdown().unwrap();
        assert!(runtime.block_on(components.node.await_termination(1000)));
        assert!(!components.client.is_running());
        components.node.clone().run();
        components.node.clone().run();
        assert!(runtime.block_on(components.node.await_termination(0)));
    }

    #[test]
    fn running_twice_retains_the_same_native_thread() {
        let components = components();
        components.node.clone().run();
        let thread = components
            .node
            .lifecycle
            .state
            .lock()
            .unwrap()
            .thread
            .as_ref()
            .unwrap()
            .thread()
            .id();
        components.node.clone().run();
        assert_eq!(
            components
                .node
                .lifecycle
                .state
                .lock()
                .unwrap()
                .thread
                .as_ref()
                .unwrap()
                .thread()
                .id(),
            thread
        );
        // The whitelist is empty, so the actual upstream node exits without network I/O.
        assert!(executor().block_on(components.node.await_termination(1000)));
    }
}
