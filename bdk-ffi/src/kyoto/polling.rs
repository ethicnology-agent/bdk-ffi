//! Native-only event consumption for leased owners. No foreign callback is stored here.
use super::{BlockId, CbfError, Info, ScanProgress, Update, WalletUpdates, Warning};
use bdk_kyoto::{bip157::tokio, LoggingSubscribers};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

type Batch = HashMap<String, Arc<Update>>;
const BATCH_CAPACITY: usize = 8;
const LOG_CAPACITY: usize = 64;
const QUEUE_FULL: &str = "wallet update queue reached capacity (8); drain, apply and persist every batch, then rebuild the node";

#[derive(Default)]
struct Queues {
    batches: VecDeque<Batch>,
    info: VecDeque<Info>,
    warnings: VecDeque<Warning>,
    synced_tip: Option<BlockId>,
    last_error: Option<String>,
    info_dropped: u64,
    warnings_dropped: u64,
}

#[derive(Default)]
pub(super) struct Polling {
    queues: Mutex<Queues>,
}

impl std::fmt::Debug for Polling {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Polling").finish_non_exhaustive()
    }
}

impl Polling {
    pub(super) fn new() -> Self {
        Self::default()
    }

    pub(super) fn poll_updates(&self) -> Option<Batch> {
        self.queues.lock().unwrap().batches.pop_front()
    }

    pub(super) fn drain_info(&self) -> Vec<Info> {
        self.queues.lock().unwrap().info.drain(..).collect()
    }

    pub(super) fn drain_warnings(&self) -> Vec<Warning> {
        self.queues.lock().unwrap().warnings.drain(..).collect()
    }

    pub(super) fn snapshot(&self) -> (Option<BlockId>, Option<String>, u64, u64) {
        let queues = self.queues.lock().unwrap();
        (
            queues.synced_tip.clone(),
            queues.last_error.clone(),
            queues.info_dropped,
            queues.warnings_dropped,
        )
    }

    pub(super) fn error(&self, message: impl Into<String>) {
        self.queues.lock().unwrap().last_error = Some(message.into());
    }

    fn info(&self, value: Info) {
        Self::push_info(&mut self.queues.lock().unwrap(), value);
    }

    fn push_info(queues: &mut Queues, value: Info) {
        // Keep only the latest of each progress kind. Remove then append so the remaining
        // diagnostic events retain their occurrence order, even across a reorg/rescan.
        let is_same_progress = |previous: &Info| {
            matches!(
                (previous, &value),
                (Info::NewChainHeight { .. }, Info::NewChainHeight { .. })
                    | (
                        Info::CfHeadersProgress { .. },
                        Info::CfHeadersProgress { .. }
                    )
                    | (Info::FiltersProgress { .. }, Info::FiltersProgress { .. })
            )
        };
        if let Some(index) = queues.info.iter().position(is_same_progress) {
            queues.info.remove(index);
            queues.info_dropped = queues.info_dropped.saturating_add(1);
        }
        if queues.info.len() == LOG_CAPACITY {
            queues.info.pop_front();
            queues.info_dropped = queues.info_dropped.saturating_add(1);
        }
        queues.info.push_back(value);
    }

    fn warning(&self, value: Warning) {
        let mut queues = self.queues.lock().unwrap();
        if queues.warnings.len() == LOG_CAPACITY {
            queues.warnings.pop_front();
            queues.warnings_dropped = queues.warnings_dropped.saturating_add(1);
        }
        queues.warnings.push_back(value);
    }

    /// Commit a whole completed boundary without suspension. False requires terminating the
    /// node before polling another boundary. The just-completed batch is always retained.
    fn enqueue(&self, batch: Batch) -> bool {
        let mut queues = self.queues.lock().unwrap();
        assert!(queues.batches.len() < BATCH_CAPACITY);
        if let Some(cp) = batch.values().find_map(|update| update.0.chain.as_ref()) {
            let tip: BlockId = cp.block_id().into();
            queues.synced_tip = Some(tip.clone());
            Self::push_info(&mut queues, Info::Synced { tip });
        }
        queues.batches.push_back(batch);
        if queues.batches.len() == BATCH_CAPACITY {
            queues.last_error = Some(QUEUE_FULL.into());
            return false;
        }
        true
    }
}

#[derive(Debug)]
pub(super) struct PollingWorker {
    logging: LoggingSubscribers,
    updates: WalletUpdates,
    progress: ScanProgress,
    output: Arc<Polling>,
}

impl PollingWorker {
    pub(super) fn new(
        logging: LoggingSubscribers,
        updates: WalletUpdates,
        start_height: u32,
        output: Arc<Polling>,
    ) -> Self {
        Self {
            logging,
            updates,
            progress: ScanProgress::new(start_height),
            output,
        }
    }

    pub(super) async fn run(self) {
        run_sources(self.updates, self.logging, self.progress, self.output).await;
    }
}

trait BatchSource: Send {
    fn next(&mut self) -> impl std::future::Future<Output = Result<Batch, CbfError>> + Send;
}

impl BatchSource for WalletUpdates {
    async fn next(&mut self) -> Result<Batch, CbfError> {
        next_batch(self).await
    }
}

async fn run_sources(
    mut updates: impl BatchSource,
    mut logging: LoggingSubscribers,
    mut progress: ScanProgress,
    output: Arc<Polling>,
) {
    let mut info_open = true;
    let mut warnings_open = true;
    loop {
        tokio::select! {
            batch = updates.next() => {
                match batch {
                    Ok(batch) => {
                        if !output.enqueue(batch) { return; }
                    },
                    Err(_) => {
                        output.error("wallet update stream stopped");
                        return;
                    }
                }
            },
            value = logging.info_subscriber.recv(), if info_open => {
                match value {
                    Some(value) => output.info(progress.map(value)),
                    None => info_open = false,
                }
            },
            value = logging.warning_subscriber.recv(), if warnings_open => {
                match value {
                    Some(value) => output.warning(value.into()),
                    None => warnings_open = false,
                }
            },
        }
    }
}

async fn next_batch(receiver: &mut WalletUpdates) -> Result<Batch, CbfError> {
    match receiver {
        WalletUpdates::Single {
            descriptor_id,
            subscriber,
        } => {
            let update = subscriber
                .update()
                .await
                .map_err(|_| CbfError::NodeStopped)?;
            Ok(HashMap::from([(
                descriptor_id.clone(),
                Arc::new(Update(update)),
            )]))
        }
        WalletUpdates::Multiple(subscriber) => Ok(subscriber
            .updates()
            .await
            .map_err(|_| CbfError::NodeStopped)?
            .map(|(id, update)| (id.to_string(), Arc::new(Update(update))))
            .collect()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_wallet::bitcoin::{hashes::Hash, BlockHash};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn batch(height: u32) -> Batch {
        ["wallet-a", "wallet-b"]
            .iter()
            .map(|id| {
                let cp = bdk_wallet::chain::CheckPoint::new(bdk_wallet::chain::BlockId {
                    height,
                    hash: BlockHash::from_byte_array([height as u8; 32]),
                });
                (
                    id.to_string(),
                    Arc::new(Update(bdk_wallet::Update {
                        chain: Some(cp),
                        ..Default::default()
                    })),
                )
            })
            .collect()
    }

    #[test]
    fn polls_preserve_complete_boundaries_routing_and_order() {
        let output = Polling::new();
        assert!(output.poll_updates().is_none());
        let batches: Vec<_> = (10..15).map(batch).collect();
        for batch in &batches {
            assert!(output.enqueue(batch.clone()));
        }
        for expected in batches {
            let actual = output.poll_updates().unwrap();
            assert_eq!(actual.len(), 2);
            for (id, update) in expected {
                assert!(Arc::ptr_eq(&actual[&id], &update));
            }
        }
        assert!(output.poll_updates().is_none());
        assert_eq!(output.snapshot().0.unwrap().height, 14);
        assert_eq!(output.drain_info().len(), 5);
        assert!(output.drain_info().is_empty());
        assert!(output.enqueue(batch(15)));
        assert_eq!(
            output.poll_updates().unwrap()["wallet-b"]
                .0
                .chain
                .as_ref()
                .unwrap()
                .height(),
            15
        );
    }

    #[test]
    fn queued_batches_survive_expiry_and_explicit_shutdown() {
        use super::super::lifecycle::NodeLifecycle;
        use std::time::{Duration, Instant};
        for explicit in [false, true] {
            let output = Arc::new(Polling::new());
            let batches: Vec<_> = (20..23).map(batch).collect();
            for batch in &batches {
                assert!(output.enqueue(batch.clone()));
            }
            let lifecycle = Arc::new(NodeLifecycle::with_polling(
                None,
                Some(Duration::from_millis(40)),
                None,
                Some(output.clone()),
            ));
            lifecycle.spawn_for_test(std::future::pending());
            if explicit {
                lifecycle.request_stop();
            }
            let deadline = Instant::now() + Duration::from_secs(1);
            while !lifecycle.is_terminated() {
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(5));
            }
            for expected in batches {
                let actual = output.poll_updates().unwrap();
                for (id, update) in expected {
                    assert!(Arc::ptr_eq(&actual[&id], &update));
                }
            }
            assert!(output.poll_updates().is_none());
            if !explicit {
                assert!(output.snapshot().1.unwrap().contains("lease expired"));
            }
        }
    }

    #[test]
    fn progress_is_coalesced_and_diagnostics_are_bounded() {
        let output = Polling::new();
        for height in 0..200 {
            output.info(Info::NewChainHeight {
                chain_height: height,
            });
        }
        for height in 0..200 {
            output.info(Info::BlockReceived(height.to_string()));
        }
        for height in 0..200 {
            output.warning(Warning::UnexpectedSyncError {
                warning: height.to_string(),
            });
        }
        let info = output.drain_info();
        assert_eq!(info.len(), LOG_CAPACITY);
        assert!(matches!(&info[0], Info::BlockReceived(value) if value == "136"));
        let warnings = output.drain_warnings();
        assert_eq!(warnings.len(), LOG_CAPACITY);
        assert!(
            matches!(&warnings[0], Warning::UnexpectedSyncError { warning } if warning == "136")
        );
        assert_eq!(output.snapshot().2, 336);
        assert_eq!(output.snapshot().3, 136);
        assert!(output.drain_warnings().is_empty());
    }

    struct TestSource {
        receive: tokio::sync::mpsc::UnboundedReceiver<Batch>,
        consumed: Arc<AtomicUsize>,
    }

    impl BatchSource for TestSource {
        async fn next(&mut self) -> Result<Batch, CbfError> {
            let batch = self.receive.recv().await.ok_or(CbfError::NodeStopped)?;
            self.consumed.fetch_add(1, Ordering::SeqCst);
            Ok(batch)
        }
    }

    #[tokio::test]
    async fn production_pump_stops_at_capacity_before_consuming_another_boundary() {
        let output = Arc::new(Polling::new());
        let consumed = Arc::new(AtomicUsize::new(0));
        let (send, receive) = tokio::sync::mpsc::unbounded_channel();
        let batches: Vec<_> = (1..=9).map(batch).collect();
        for batch in &batches {
            send.send(batch.clone()).unwrap();
        }
        let (info_send, info_subscriber) = tokio::sync::mpsc::channel(32);
        let (warning_send, warning_subscriber) = tokio::sync::mpsc::channel(512);
        info_send
            .send(bdk_kyoto::Info::SuccessfulHandshake)
            .await
            .unwrap();
        warning_send
            .send(bdk_kyoto::Warning::PeerTimedOut)
            .await
            .unwrap();
        let source = TestSource {
            receive,
            consumed: consumed.clone(),
        };
        let lifecycle = Arc::new(super::super::lifecycle::NodeLifecycle::with_polling(
            None,
            Some(std::time::Duration::from_secs(1)),
            None,
            Some(output.clone()),
        ));
        let native_output = output.clone();
        lifecycle.spawn_for_test(async move {
            run_sources(
                source,
                LoggingSubscribers {
                    info_subscriber,
                    warning_subscriber,
                },
                ScanProgress::new(0),
                native_output,
            )
            .await;
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while !lifecycle.is_terminated() {
            assert!(
                std::time::Instant::now() < deadline,
                "overflow must terminate the native runtime"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(lifecycle.stop_requested());
        assert_eq!(consumed.load(Ordering::SeqCst), BATCH_CAPACITY);
        assert!(output.snapshot().1.unwrap().contains("rebuild"));
        for expected in batches.into_iter().take(BATCH_CAPACITY) {
            let actual = output.poll_updates().unwrap();
            for (id, update) in expected {
                assert!(Arc::ptr_eq(&actual[&id], &update));
            }
        }
        assert!(output.poll_updates().is_none());
    }
}
