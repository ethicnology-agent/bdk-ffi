mod lifecycle;
mod polling;

use bdk_kyoto::bip157;
use bdk_kyoto::bip157::lookup_host;
use bdk_kyoto::bip157::tokio;
use bdk_kyoto::bip157::AddrV2;
use bdk_kyoto::bip157::Network;
use bdk_kyoto::bip157::Node;
use bdk_kyoto::bip157::ServiceFlags;
use bdk_kyoto::builder::Builder as BDKCbfBuilder;
use bdk_kyoto::builder::BuilderExt;
use bdk_kyoto::HashCheckpoint;
use bdk_kyoto::Receiver;
use bdk_kyoto::RejectReason;
use bdk_kyoto::Requester;
use bdk_kyoto::TrustedPeer;
use bdk_kyoto::UpdateSubscriber;
use bdk_kyoto::Warning as Warn;
use lifecycle::NodeLifecycle;
use polling::{Polling, PollingWorker};

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;

use crate::bitcoin::Transaction;
use crate::bitcoin::Wtxid;
use crate::bitcoin::{BlockHash, Header};
use crate::error::CbfError;
use crate::types::BlockId;
use crate::types::Update;
use crate::wallet::Wallet;
use crate::FeeRate;

const DEFAULT_CONNECTIONS: u8 = 2;
const TCP_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);
const MESSAGE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

/// Receive a [`CbfClient`] and [`CbfNode`].
#[derive(Debug, uniffi::Record)]
pub struct CbfComponents {
    /// Publish events to the node, like broadcasting transactions or adding scripts.
    pub client: Arc<CbfClient>,
    /// The node to run and fetch transactions for a [`Wallet`].
    pub node: Arc<CbfNode>,
}

/// A [`CbfClient`] handles wallet updates from a [`CbfNode`].
/// Dropping the last client reference requests node cancellation. Pending foreign
/// calls can retain a client reference until their futures are cancelled or released.
#[derive(Debug, uniffi::Object)]
pub struct CbfClient {
    sender: Arc<Requester>,
    lifecycle: Arc<NodeLifecycle>,
    legacy: Option<LegacyReceivers>,
    polling: Option<Arc<Polling>>,
}

#[derive(Debug)]
struct LegacyReceivers {
    info_rx: Mutex<InfoReceiver>,
    sync_info_tx: tokio::sync::mpsc::UnboundedSender<Info>,
    warning_rx: Mutex<Receiver<bdk_kyoto::Warning>>,
    update_rx: Mutex<WalletUpdates>,
}

#[derive(Debug)]
struct InfoReceiver {
    native: Receiver<bdk_kyoto::Info>,
    synced: tokio::sync::mpsc::UnboundedReceiver<Info>,
    progress: ScanProgress,
}

#[derive(Debug)]
enum WalletUpdates {
    Single {
        descriptor_id: String,
        subscriber: UpdateSubscriber<bdk_kyoto::wallets::Single>,
    },
    Multiple(UpdateSubscriber<bdk_kyoto::wallets::Multiple>),
}

/// A [`CbfNode`] gathers transactions for a [`Wallet`].
/// To receive [`Update`] for [`Wallet`], refer to the
/// [`CbfClient`]. The [`CbfNode`] will run until instructed
/// to stop. Dropping its last reference also requests cancellation.
#[derive(Debug, uniffi::Object)]
pub struct CbfNode {
    lifecycle: Arc<NodeLifecycle>,
}

#[uniffi::export]
impl CbfNode {
    /// Acknowledge actual thread and runtime teardown without waiting or callbacks.
    /// Before run this is false until shutdown. True results include a completed native join.
    pub fn is_terminated(&self) -> bool {
        self.lifecycle.is_terminated()
    }

    /// Start the node on its owned OS thread and immediately return.
    /// Subsequent calls have no effect. A configured owner lease starts here.
    pub fn run(self: Arc<Self>) {
        self.lifecycle.run();
    }

    /// Wait at most `timeout_millis` for the native thread and its Tokio runtime to exit.
    ///
    /// A false result means the caller must retain ownership and may wait again. An OS DNS
    /// resolver that cannot be interrupted can delay runtime teardown beyond this timeout.
    /// Before run, returns false until the client has shut down and the stored node is dropped.
    pub async fn await_termination(&self, timeout_millis: u64) -> bool {
        self.lifecycle
            .clone()
            .await_termination(Duration::from_millis(timeout_millis))
            .await
    }
}

/// Build a BIP 157/158 light client to fetch transactions for a `Wallet`.
///
/// Options:
/// * List of `Peer`: Bitcoin full-nodes for the light client to connect to. May be empty.
/// * `connections`: The number of connections for the light client to maintain.
/// * `scan_type`: Sync from the wallet checkpoint or recover from an exact checkpoint.
///
/// Recovery checks a finite script range selected by `used_script_index`, starting
/// strictly after the chosen height/hash checkpoint. This bound is a script count,
/// not an inclusive derivation index or an Electrum stop gap. It must cover every
/// address that may have been used; the builder does not discover an arbitrary range.
#[derive(Clone, uniffi::Object)]
pub struct CbfBuilder {
    connections: u8,
    handshake_timeout: Duration,
    response_timeout: Duration,
    scan_type: ScanType,
    socks5_proxy: Option<Socks5Proxy>,
    peers: Vec<Peer>,
    whitelist_only: bool,
    owner_lease: Option<Duration>,
}

#[allow(clippy::new_without_default)]
#[uniffi::export]
impl CbfBuilder {
    /// Start a new [`CbfBuilder`]
    #[uniffi::constructor]
    pub fn new() -> Self {
        CbfBuilder {
            connections: DEFAULT_CONNECTIONS,
            handshake_timeout: TCP_HANDSHAKE_TIMEOUT,
            response_timeout: MESSAGE_RESPONSE_TIMEOUT,
            scan_type: ScanType::default(),
            socks5_proxy: None,
            peers: Vec::new(),
            whitelist_only: false,
            owner_lease: None,
        }
    }

    /// Enable callback-free polling with a renewable owner lease, starting at `run()`.
    /// A zero TTL or a TTL above one day is rejected. Legacy builds have no lease.
    pub fn owner_lease_millis(&self, ttl_millis: u64) -> Result<Arc<Self>, CbfError> {
        if ttl_millis == 0 || ttl_millis > 86_400_000 {
            return Err(CbfError::InvalidConfiguration {
                reason: "owner lease TTL must be between 1 and 86400000 milliseconds".into(),
            });
        }
        Ok(Arc::new(Self {
            owner_lease: Some(Duration::from_millis(ttl_millis)),
            ..self.clone()
        }))
    }

    /// The number of connections for the light client to maintain. Default is two.
    pub fn connections(&self, connections: u8) -> Arc<Self> {
        Arc::new(CbfBuilder {
            connections,
            ..self.clone()
        })
    }

    /// Select routine syncing or recovery from an exact checkpoint.
    pub fn scan_type(&self, scan_type: ScanType) -> Arc<Self> {
        Arc::new(CbfBuilder {
            scan_type,
            ..self.clone()
        })
    }

    /// Bitcoin full-nodes to attempt a connection with.
    pub fn peers(&self, peers: Vec<Peer>) -> Arc<Self> {
        Arc::new(CbfBuilder {
            peers,
            ..self.clone()
        })
    }

    /// Configure the time in milliseconds that a node has to:
    /// 1. Respond to the initial connection
    /// 2. Respond to a request
    pub fn configure_timeout_millis(&self, handshake: u64, response: u64) -> Arc<Self> {
        Arc::new(CbfBuilder {
            handshake_timeout: Duration::from_millis(handshake),
            response_timeout: Duration::from_millis(response),
            ..self.clone()
        })
    }

    /// Configure connections to be established through a `Socks5 proxy. The vast majority of the
    /// time, the connection is to a local Tor daemon, which is typically exposed at
    /// `127.0.0.1:9050`.
    pub fn socks5_proxy(&self, proxy: Socks5Proxy) -> Arc<Self> {
        Arc::new(CbfBuilder {
            socks5_proxy: Some(proxy),
            ..self.clone()
        })
    }

    /// When set, only connect to peers configured at build time. This will skip DNS and will not
    /// use gossiped nodes.
    pub fn only_configured_peers(&self) -> Arc<Self> {
        Arc::new(CbfBuilder {
            whitelist_only: true,
            ..self.clone()
        })
    }

    /// Construct a [`CbfComponents`] for a [`Wallet`].
    pub fn build(&self, wallet: &Wallet) -> CbfComponents {
        let wallet = wallet.get_wallet();

        let mut trusted_peers = Vec::new();
        for peer in self.peers.iter() {
            trusted_peers.push(peer.clone().into());
        }

        let recovery_checkpoint = match self.scan_type.clone() {
            ScanType::Sync => None,
            ScanType::Recovery { checkpoint, .. } => Some(recovery_checkpoint(&wallet, checkpoint)),
        };
        let start_height = recovery_checkpoint
            .map(|cp| cp.height)
            .unwrap_or_else(|| sync_start_height(&wallet));
        let descriptor_id = wallet_descriptor_id(&wallet);
        let builder = self.node_builder(wallet.network(), trusted_peers);

        let client = match self.scan_type {
            ScanType::Sync => builder.build_with_wallet(
                &wallet,
                bdk_kyoto::SyncConfig::sync_from_last_checkpoint().build(),
            ),
            ScanType::Recovery {
                used_script_index, ..
            } => {
                let sync = bdk_kyoto::SyncConfig::wallet_recovery_sync(
                    recovery_checkpoint.expect("recovery checkpoint was resolved"),
                    used_script_index,
                );
                let sync = if matches!(
                    self.scan_type,
                    ScanType::Recovery {
                        checkpoint: RecoveryPoint::LastCheckpoint,
                        ..
                    }
                ) {
                    sync.reuse_persisted_history()
                } else {
                    sync
                };
                builder.build_with_wallet(&wallet, sync.build())
            }
        }
        .expect("networks match by definition");
        let (client, logging, subscriber) = client.subscribe();
        let (client, node) = client.managed_start();
        components(
            client.requester(),
            node,
            logging,
            WalletUpdates::Single {
                descriptor_id,
                subscriber,
            },
            start_height,
            self.owner_lease,
        )
    }

    /// Build one long-running node for a fixed set of wallets on the same network.
    ///
    /// Only `ScanType::Sync` is supported. For recovery, insert a trusted birthday
    /// checkpoint into the wallet before building and create/load it with a lookahead
    /// covering the recovery script window (for example 1,000 per keychain).
    /// The node starts at the minimum wallet checkpoint, with up to seven blocks of
    /// rewind where known checkpoints exist. Rebuild the node when its wallet set changes.
    /// Wallets must have distinct external descriptor ids.
    pub fn build_with_wallets(&self, wallets: Vec<Arc<Wallet>>) -> Result<CbfComponents, CbfError> {
        if !matches!(self.scan_type, ScanType::Sync) {
            return Err(CbfError::InvalidConfiguration {
                reason: "multi-wallet nodes require ScanType::Sync; seed birthday checkpoints on the wallets".into(),
            });
        }
        let network = wallets
            .first()
            .ok_or_else(|| CbfError::InvalidConfiguration {
                reason: "at least one wallet is required".into(),
            })?
            .network();
        // Validate before taking locks so duplicate references cannot deadlock.
        let mut ids = HashSet::new();
        for wallet in &wallets {
            if wallet.network() != network {
                return Err(CbfError::InvalidConfiguration {
                    reason: "wallet networks must match".into(),
                });
            }
            if !ids.insert(wallet.descriptor_id(bdk_wallet::KeychainKind::External)) {
                return Err(CbfError::InvalidConfiguration {
                    reason: "external descriptor ids must be unique".into(),
                });
            }
        }
        // A stable lock order also permits concurrent builders sharing wallet objects.
        let mut wallets = wallets;
        wallets.sort_by_key(|wallet| Arc::as_ptr(wallet) as usize);
        let guards: Vec<_> = wallets.iter().map(|wallet| wallet.get_wallet()).collect();
        let start_height = guards
            .iter()
            .map(|wallet| sync_start_height(wallet))
            .min()
            .unwrap();
        let client = self
            .node_builder(
                network,
                self.peers.iter().cloned().map(Into::into).collect(),
            )
            .build_with_wallets(
                guards
                    .iter()
                    .map(|wallet| {
                        (
                            &***wallet,
                            bdk_kyoto::SyncConfig::sync_from_last_checkpoint().build(),
                        )
                    })
                    .collect(),
            )
            .map_err(|error| CbfError::InvalidConfiguration {
                reason: error.to_string(),
            })?;
        let (client, logging, subscriber) = client.subscribe();
        let (client, node) = client.managed_start();
        Ok(components(
            client.requester(),
            node,
            logging,
            WalletUpdates::Multiple(subscriber),
            start_height,
            self.owner_lease,
        ))
    }
}

impl CbfBuilder {
    fn node_builder(&self, network: Network, trusted_peers: Vec<TrustedPeer>) -> BDKCbfBuilder {
        let mut builder = BDKCbfBuilder::new(network)
            .required_peers(self.connections)
            .handshake_timeout(self.handshake_timeout)
            .response_timeout(self.response_timeout)
            .add_peers(trusted_peers);
        if let Some(proxy) = &self.socks5_proxy {
            builder = builder.socks5_proxy(SocketAddr::new(proxy.address.inner, proxy.port));
        }
        if self.whitelist_only {
            builder = builder.whitelist_only();
        }
        builder
    }
}

// Keep the progress denominator aligned with Kyoto's bounded-height reorg rewind.
fn sync_start_height(wallet: &bdk_wallet::Wallet) -> u32 {
    sync_start_checkpoint(wallet).height
}

fn sync_start_checkpoint(wallet: &bdk_wallet::Wallet) -> HashCheckpoint {
    let tip = wallet.latest_checkpoint();
    let floor = tip.height().saturating_sub(7);
    let checkpoint = tip
        .iter()
        .take_while(|cp| cp.height() >= floor)
        .last()
        .unwrap();
    HashCheckpoint::new(checkpoint.height(), checkpoint.hash())
}

fn recovery_checkpoint(wallet: &bdk_wallet::Wallet, point: RecoveryPoint) -> HashCheckpoint {
    match point {
        RecoveryPoint::GenesisBlock => HashCheckpoint::from_genesis(wallet.network()),
        RecoveryPoint::SegwitActivation if wallet.network() == Network::Bitcoin => {
            HashCheckpoint::segwit_activation()
        }
        RecoveryPoint::TaprootActivation if wallet.network() == Network::Bitcoin => {
            HashCheckpoint::taproot_activation()
        }
        RecoveryPoint::SegwitActivation | RecoveryPoint::TaprootActivation => {
            HashCheckpoint::from_genesis(wallet.network())
        }
        RecoveryPoint::Other { birthday } => HashCheckpoint::new(birthday.height, birthday.hash.0),
        RecoveryPoint::LastCheckpoint => sync_start_checkpoint(wallet),
    }
}

fn wallet_descriptor_id(wallet: &bdk_wallet::Wallet) -> String {
    use bdk_wallet::chain::DescriptorExt;
    wallet
        .public_descriptor(bdk_wallet::KeychainKind::External)
        .descriptor_id()
        .to_string()
}

fn components(
    requester: Requester,
    node: Node,
    logging: bdk_kyoto::LoggingSubscribers,
    updates: WalletUpdates,
    start_height: u32,
    owner_lease: Option<Duration>,
) -> CbfComponents {
    let (sync_info_tx, synced) = tokio::sync::mpsc::unbounded_channel();
    let (legacy, polling, worker) = if owner_lease.is_some() {
        let polling = Arc::new(Polling::new());
        let worker = PollingWorker::new(logging, updates, start_height, polling.clone());
        (None, Some(polling), Some(worker))
    } else {
        (
            Some(LegacyReceivers {
                info_rx: Mutex::new(InfoReceiver {
                    native: logging.info_subscriber,
                    synced,
                    progress: ScanProgress::new(start_height),
                }),
                sync_info_tx,
                warning_rx: Mutex::new(logging.warning_subscriber),
                update_rx: Mutex::new(updates),
            }),
            None,
            None,
        )
    };
    let lifecycle = Arc::new(NodeLifecycle::with_polling(
        Some(node),
        owner_lease,
        worker,
        polling.clone(),
    ));
    CbfComponents {
        node: Arc::new(CbfNode {
            lifecycle: lifecycle.clone(),
        }),
        client: Arc::new(CbfClient {
            sender: Arc::new(requester),
            lifecycle,
            legacy,
            polling,
        }),
    }
}

/// Snapshot available synchronously without registering any foreign callback.
#[derive(Debug, uniffi::Record)]
pub struct CbfStatus {
    pub running: bool,
    pub terminated: bool,
    /// Latest prepared boundary that completed filter sync to tip, excluding partial progress.
    pub synced_tip: Option<BlockId>,
    pub last_error: Option<String>,
    /// Diagnostic messages replaced or discarded by the bounded info queue.
    pub info_dropped: u64,
    /// Oldest warnings discarded by the bounded warning queue.
    pub warnings_dropped: u64,
}

/// One safe-to-persist scan boundary for every wallet in the node.
#[derive(Clone, uniffi::Record)]
pub struct CbfUpdateBatch {
    /// Updates keyed by each wallet's public external descriptor identifier.
    pub updates: HashMap<String, Arc<Update>>,
    /// Verified checkpoint reached after checking filters and applying matched blocks.
    /// A wallet already persisted ahead retains its prior chain tip until scanning catches up.
    pub scanned_tip: BlockId,
    /// Whether this boundary also completed the node's current filter sync to its tip.
    pub synced_to_tip: bool,
}

impl std::fmt::Debug for CbfUpdateBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CbfUpdateBatch")
            .field("wallet_count", &self.updates.len())
            .field("scanned_tip", &self.scanned_tip)
            .field("synced_to_tip", &self.synced_to_tip)
            .finish()
    }
}

#[uniffi::export]
impl CbfClient {
    /// Remove the oldest complete per-wallet batch, or return None immediately.
    /// Requires owner_lease_millis. Batches remain drainable after termination.
    /// This includes intermediate checkpoints; use poll_update_batch for completion metadata.
    pub fn poll_updates(&self) -> Result<Option<HashMap<String, Arc<Update>>>, CbfError> {
        Ok(self.polling()?.poll_updates())
    }

    /// Remove the oldest complete boundary with its scan checkpoint and completion signal.
    /// Requires owner_lease_millis. Use one polling method: poll_updates consumes the same FIFO
    /// while discarding metadata. Apply and persist all wallet updates before the next poll.
    pub fn poll_update_batch(&self) -> Result<Option<CbfUpdateBatch>, CbfError> {
        Ok(self.polling()?.poll_update_batch())
    }

    /// Drain bounded diagnostic information without waiting or foreign callbacks.
    pub fn drain_info(&self) -> Result<Vec<Info>, CbfError> {
        Ok(self.polling()?.drain_info())
    }

    /// Drain bounded warnings without waiting or foreign callbacks.
    pub fn drain_warnings(&self) -> Result<Vec<Warning>, CbfError> {
        Ok(self.polling()?.drain_warnings())
    }

    /// Extend a live owner's deadline by its configured TTL. Cannot revive an expired node.
    pub fn renew_lease(&self) -> Result<(), CbfError> {
        self.polling()?;
        self.lifecycle.renew_lease()
    }

    /// Read native state without awaiting or registering a foreign completion.
    pub fn status(&self) -> CbfStatus {
        let (synced_tip, last_error, info_dropped, warnings_dropped) = self
            .polling
            .as_ref()
            .map(|polling| polling.snapshot())
            .unwrap_or((None, None, 0, 0));
        CbfStatus {
            running: self.is_running(),
            terminated: self.lifecycle.is_terminated(),
            synced_tip,
            last_error,
            info_dropped,
            warnings_dropped,
        }
    }

    /// Return the next available info message from a node. If none is returned, the node has stopped.
    pub async fn next_info(&self) -> Result<Info, CbfError> {
        let mut info = self.legacy()?.info_rx.lock().await;
        let InfoReceiver {
            native,
            synced,
            progress,
        } = &mut *info;
        tokio::select! {
            biased;
            value = synced.recv() => value.ok_or(CbfError::NodeStopped),
            value = native.recv() => value.map(|value| progress.map(value)).ok_or(CbfError::NodeStopped),
        }
    }

    /// Return the next available warning message from a node. If none is returned, the node has stopped.
    pub async fn next_warning(&self) -> Result<Warning, CbfError> {
        let mut warn_rx = self.legacy()?.warning_rx.lock().await;
        warn_rx
            .recv()
            .await
            .map(|warn| warn.into())
            .ok_or(CbfError::NodeStopped)
    }

    /// Wait until filters and matched blocks reach a tip, then return a wallet update.
    /// Call repeatedly while the node is running; the next call waits for a new sync boundary.
    /// Cancellation preserves pending work. Only valid for the single-wallet builder.
    /// Apply and persist each returned update before requesting another.
    pub async fn update(&self) -> Result<Update, CbfError> {
        let mut receiver = self.legacy()?.update_rx.lock().await;
        let WalletUpdates::Single { subscriber, .. } = &mut *receiver else {
            return Err(CbfError::InvalidConfiguration {
                reason: "use updates() with a multi-wallet node".into(),
            });
        };
        let update = subscriber
            .update()
            .await
            .map_err(|_| CbfError::NodeStopped)?;
        self.notify_synced(&update);
        Ok(Update(update))
    }

    /// Wait for the next caught-up boundary and route updates by public external descriptor id.
    /// Works with both builders. Call in a continual loop, applying/persisting every update
    /// to the wallet whose `descriptor_id(External)` matches its key. Cancellation is safe.
    pub async fn updates(&self) -> Result<HashMap<String, Arc<Update>>, CbfError> {
        let mut receiver = self.legacy()?.update_rx.lock().await;
        let updates: HashMap<String, Arc<Update>> = match &mut *receiver {
            WalletUpdates::Single {
                descriptor_id,
                subscriber,
            } => {
                let update = subscriber
                    .update()
                    .await
                    .map_err(|_| CbfError::NodeStopped)?;
                HashMap::from([(descriptor_id.clone(), Arc::new(Update(update)))])
            }
            WalletUpdates::Multiple(subscriber) => subscriber
                .updates()
                .await
                .map_err(|_| CbfError::NodeStopped)?
                .map(|(id, update)| (id.to_string(), Arc::new(Update(update))))
                .collect(),
        };
        if let Some(update) = updates.values().next() {
            self.notify_synced(&update.0);
        }
        Ok(updates)
    }

    /// Recheck filters strictly after `height`, bounded by the node's configured start.
    /// This does not add wallets or scripts to the node's fixed wallet snapshot.
    /// Call after the first update/Synced boundary: bip157 ignores rescans during header sync.
    pub fn rescan_from(&self, height: u32) -> Result<(), CbfError> {
        self.sender.rescan_from(height).map_err(From::from)
    }

    /// Recheck filters after the configured start checkpoint.
    /// Call after the first update/Synced boundary; ignored during header sync.
    pub fn rescan(&self) -> Result<(), CbfError> {
        self.sender.rescan().map_err(From::from)
    }

    /// The height and hash of the node's current chain of most work.
    /// Header sync may be ahead of wallet/filter sync; use returned updates or `Info::Synced`
    /// to identify a caught-up wallet boundary.
    pub async fn chain_tip(&self) -> Result<BlockId, CbfError> {
        let cp = self
            .sender
            .chain_tip()
            .await
            .map_err(|_| CbfError::NodeStopped)?;
        Ok(BlockId {
            height: cp.height,
            hash: Arc::new(BlockHash(cp.hash)),
        })
    }

    /// Look up a header in the node's locally synced header chain.
    pub async fn get_header(&self, height: u32) -> Result<Option<Header>, CbfError> {
        self.sender
            .get_header(height)
            .await
            .map_err(|_| CbfError::NodeStopped)
            .map(|header| header.map(|indexed| indexed.header.into()))
    }

    /// Submit one transaction, or a parent followed by its spending child, to a random peer.
    /// Returns when data was sent to at least one peer, not an acceptance or confirmation.
    pub async fn submit_package(
        &self,
        transactions: Vec<Arc<Transaction>>,
    ) -> Result<Arc<Wtxid>, CbfError> {
        let package =
            bip157::Package::from_vec(transactions.iter().map(|tx| tx.as_ref().into()).collect())
                .map_err(|error| CbfError::InvalidPackage {
                reason: error.to_string(),
            })?;
        self.sender
            .submit_package(package)
            .await
            .map_err(From::from)
            .map(|wtxid| Arc::new(Wtxid(wtxid)))
    }

    /// Broadcast a transaction to the network, erroring if the node has stopped running.
    pub async fn broadcast(&self, transaction: &Transaction) -> Result<Arc<Wtxid>, CbfError> {
        let tx: bip157::Transaction = transaction.into();
        self.sender
            .submit_package(tx)
            .await
            .map_err(From::from)
            .map(|wtxid| Arc::new(Wtxid(wtxid)))
    }

    /// The minimum fee rate required to broadcast a transcation to all connected peers.
    pub async fn min_broadcast_feerate(&self) -> Result<Arc<FeeRate>, CbfError> {
        self.sender
            .broadcast_min_feerate()
            .await
            .map_err(|_| CbfError::NodeStopped)
            .map(|fee| Arc::new(FeeRate(fee)))
    }

    /// Fetch the average fee rate for a block by requesting it from a peer. Not recommend for
    /// resource-limited devices.
    pub async fn average_fee_rate(
        &self,
        blockhash: Arc<BlockHash>,
    ) -> Result<Arc<FeeRate>, CbfError> {
        let fee_rate = self
            .sender
            .average_fee_rate(blockhash.0)
            .await
            .map_err(|_| CbfError::NodeStopped)?;
        Ok(Arc::new(fee_rate.into()))
    }

    /// Add another [`Peer`] to attempt a connection with.
    pub fn connect(&self, peer: Peer) -> Result<(), CbfError> {
        self.sender
            .add_peer(peer)
            .map_err(|_| CbfError::NodeStopped)
    }

    /// Query a Bitcoin DNS seeder using the configured resolver.
    ///
    /// This is **not** a generic DNS implementation. Host names are prefixed with a `x849` to filter
    /// for compact block filter nodes from the seeder. For example `dns.myseeder.com` will be queried
    /// as `x849.dns.myseeder.com`. This has no guarantee to return any `IpAddr`.
    pub fn lookup_host(&self, hostname: String) -> Vec<Arc<IpAddress>> {
        let node_handle = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(lookup_host(hostname))
        });
        let nodes = node_handle.join().unwrap_or_default();
        nodes
            .into_iter()
            .map(|ip| Arc::new(IpAddress { inner: ip }))
            .collect()
    }

    /// Get the list of current connections.
    pub async fn peer_info(&self) -> Result<Vec<Arc<IpAddress>>, CbfError> {
        let peers = self
            .sender
            .peer_info()
            .await
            .map_err(|_| CbfError::NodeStopped)?;
        Ok(peers
            .into_iter()
            .filter_map(|(ip, _)| match ip {
                AddrV2::Ipv4(ip) => Some(IpAddr::V4(ip)),
                AddrV2::Ipv6(ip) => Some(IpAddr::V6(ip)),
                _ => None,
            })
            .map(|ip| Arc::new(IpAddress { inner: ip }))
            .collect())
    }

    /// Count all live connections, including Tor and other address types omitted by `peer_info`.
    pub async fn peer_count(&self) -> Result<u64, CbfError> {
        self.sender
            .peer_info()
            .await
            .map_err(|_| CbfError::NodeStopped)
            .map(|peers| peers.len() as u64)
    }

    /// Check whether the node accepts requests and has not been asked to stop.
    /// Use [`CbfNode::await_termination`] to acknowledge that its native thread has exited.
    pub fn is_running(&self) -> bool {
        !self.lifecycle.stop_requested() && self.sender.is_running()
    }

    /// Request cancellation of the [`CbfNode`], including pending peer or DNS setup.
    /// Errors if the native request channel is already closed. Await the node's
    /// termination before releasing ownership of the wallet operation.
    pub fn shutdown(&self) -> Result<(), CbfError> {
        let result = self.sender.shutdown().map_err(From::from);
        self.lifecycle.request_stop();
        result
    }
}

impl CbfClient {
    fn legacy(&self) -> Result<&LegacyReceivers, CbfError> {
        self.legacy.as_ref().ok_or_else(|| CbfError::InvalidConfiguration {
            reason: "leased nodes require synchronous polling; legacy event futures are unsafe across isolate death".into(),
        })
    }

    fn polling(&self) -> Result<&Polling, CbfError> {
        self.polling
            .as_deref()
            .ok_or_else(|| CbfError::InvalidConfiguration {
                reason: "configure owner_lease_millis before building to use callback-free polling"
                    .into(),
            })
    }

    fn notify_synced(&self, update: &bdk_wallet::Update) {
        if let Some(cp) = &update.chain {
            // An unbounded send cannot suspend after the subscriber has consumed the boundary.
            let _ = self
                .legacy
                .as_ref()
                .unwrap()
                .sync_info_tx
                .send(Info::Synced {
                    tip: cp.block_id().into(),
                });
        }
    }
}

impl Drop for CbfClient {
    fn drop(&mut self) {
        self.lifecycle.request_stop();
    }
}

impl Drop for CbfNode {
    fn drop(&mut self) {
        self.lifecycle.request_stop();
    }
}

/// A log message from the node. Progress describes downloads, not persisted wallet state.
#[derive(Debug, uniffi::Enum)]
pub enum Info {
    /// All the required connections have been met. This is subject to change.
    ConnectionsMet,
    /// The node was able to successfully connect to a remote peer.
    SuccessfulHandshake,
    /// The highest downloaded block header, used as the progress denominator.
    NewChainHeight { chain_height: u32 },
    /// Compact filter header download progress over this scan's height range.
    CfHeadersProgress {
        chain_height: u32,
        headers_height: u32,
        fraction: f32,
    },
    /// Compact filter download progress over this scan's height range.
    FiltersProgress {
        chain_height: u32,
        filters_height: u32,
        fraction: f32,
    },
    /// Filters and queued matching blocks have reached this wallet update boundary.
    /// Emitted when a legacy update returns or a complete polling batch is queued.
    /// The application must still apply and persist
    /// that update. A `NewChainHeight` above this tip signals another scanning interval;
    /// lower heights may still be queued in the independent native information stream.
    Synced { tip: BlockId },
    /// A relevant block was downloaded from a peer.
    BlockReceived(String),
}

#[derive(Debug)]
struct ScanProgress {
    start_height: u32,
    chain_height: u32,
}

impl ScanProgress {
    fn new(start_height: u32) -> Self {
        Self {
            start_height,
            chain_height: start_height,
        }
    }

    fn fraction(&self, height: u32) -> f32 {
        let total = self.chain_height.saturating_sub(self.start_height);
        if total == 0 {
            return 0.0;
        }
        (height.saturating_sub(self.start_height) as f32 / total as f32).clamp(0.0, 1.0)
    }

    fn map(&mut self, value: bdk_kyoto::Info) -> Info {
        match value {
            bdk_kyoto::Info::ConnectionsMet => Info::ConnectionsMet,
            bdk_kyoto::Info::SuccessfulHandshake => Info::SuccessfulHandshake,
            bdk_kyoto::Info::NewChainHeight(chain_height) => {
                self.chain_height = chain_height;
                Info::NewChainHeight { chain_height }
            }
            bdk_kyoto::Info::CFHeadersAdded(headers_height) => Info::CfHeadersProgress {
                chain_height: self.chain_height,
                headers_height,
                fraction: self.fraction(headers_height),
            },
            bdk_kyoto::Info::FilterAdded(filters_height) => Info::FiltersProgress {
                chain_height: self.chain_height,
                filters_height,
                fraction: self.fraction(filters_height),
            },
            bdk_kyoto::Info::BlockReceived(block) => Info::BlockReceived(block.to_string()),
        }
    }
}

/// Warnings a node may issue while running.
#[derive(Debug, uniffi::Enum)]
pub enum Warning {
    /// The node is looking for connections to peers.
    NeedConnections,
    /// A connection to a peer timed out.
    PeerTimedOut,
    /// The node was unable to connect to a peer in the database.
    CouldNotConnect,
    /// A connection was maintained, but the peer does not signal for compact block filers.
    NoCompactFilters,
    /// The node has been waiting for new inv and will find new peers to avoid block withholding.
    PotentialStaleTip,
    /// A peer sent us a peer-to-peer message the node did not request.
    UnsolicitedMessage,
    /// A transaction got rejected, likely for being an insufficient fee or non-standard transaction.
    TransactionRejected {
        wtxid: String,
        reason: Option<String>,
    },
    /// The peer sent us a potential fork.
    EvaluatingFork,
    /// An unexpected error occurred processing a peer-to-peer message.
    UnexpectedSyncError { warning: String },
    /// The node failed to respond to a message sent from the client.
    RequestFailed,
}

impl From<Warn> for Warning {
    fn from(value: Warn) -> Warning {
        match value {
            Warn::NeedConnections {
                connected: _,
                required: _,
            } => Warning::NeedConnections,
            Warn::PeerTimedOut => Warning::PeerTimedOut,
            Warn::CouldNotConnect => Warning::CouldNotConnect,
            Warn::NoCompactFilters => Warning::NoCompactFilters,
            Warn::PotentialStaleTip => Warning::PotentialStaleTip,
            Warn::UnsolicitedMessage => Warning::UnsolicitedMessage,
            Warn::TransactionRejected { payload } => {
                let reason = payload.reason.map(|r| r.into_string());
                Warning::TransactionRejected {
                    wtxid: payload.wtxid.to_string(),
                    reason,
                }
            }
            Warn::EvaluatingFork => Warning::EvaluatingFork,
            Warn::UnexpectedSyncError { warning } => Warning::UnexpectedSyncError { warning },
            Warn::ChannelDropped => Warning::RequestFailed,
        }
    }
}

/// Sync a wallet from the last known block hash or recover a wallet from a specified recovery
/// point.
#[derive(Debug, Clone, Default, uniffi::Enum)]
pub enum ScanType {
    /// Sync an existing wallet from the last stored chain checkpoint.
    #[default]
    Sync,
    /// Recover an existing wallet by scanning from the specified height.
    Recovery {
        /// The estimated number of scripts the user has revealed for the wallet being recovered.
        /// If unknown, a conservative estimate, say 1,000, could be used.
        used_script_index: u32,
        /// A relevant starting point or soft fork to start the sync.
        checkpoint: RecoveryPoint,
    },
}

#[derive(Debug, Clone, Default, uniffi::Enum)]
pub enum RecoveryPoint {
    GenesisBlock,
    #[default]
    SegwitActivation,
    TaprootActivation,
    Other {
        birthday: BlockId,
    },
    /// Resume from the persisted wallet checkpoint with the normal bounded reorg rewind.
    /// Keep the original recovery script count when rebuilding an interrupted recovery.
    LastCheckpoint,
}

/// A peer to connect to over the Bitcoin peer-to-peer network.
#[derive(Clone, uniffi::Record)]
pub struct Peer {
    /// The IP address to reach the node.
    pub address: Arc<IpAddress>,
    /// The port to reach the node. If none is provided, the default
    /// port for the selected network will be used.
    pub port: Option<u16>,
    /// Does the remote node offer encrypted peer-to-peer connection.
    pub v2_transport: bool,
}

/// An IP address to connect to over TCP.
#[derive(Debug, uniffi::Object)]
#[uniffi::export(Display)]
pub struct IpAddress {
    inner: IpAddr,
}

impl core::fmt::Display for IpAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{}", self.inner)
    }
}

#[uniffi::export]
impl IpAddress {
    /// Build an IPv4 address.
    #[uniffi::constructor]
    pub fn from_ipv4(q1: u8, q2: u8, q3: u8, q4: u8) -> Self {
        Self {
            inner: IpAddr::V4(Ipv4Addr::new(q1, q2, q3, q4)),
        }
    }

    /// Build an IPv6 address.
    #[allow(clippy::too_many_arguments)]
    #[uniffi::constructor]
    pub fn from_ipv6(a: u16, b: u16, c: u16, d: u16, e: u16, f: u16, g: u16, h: u16) -> Self {
        Self {
            inner: IpAddr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h)),
        }
    }
}

/// A proxy to route network traffic, most likely through a Tor daemon. Normally this proxy is
/// exposed at 127.0.0.1:9050.
#[derive(Debug, Clone, uniffi::Record)]
pub struct Socks5Proxy {
    /// The IP address, likely `127.0.0.1`
    pub address: Arc<IpAddress>,
    /// The listening port, likely `9050`
    pub port: u16,
}

impl From<Peer> for TrustedPeer {
    fn from(peer: Peer) -> Self {
        let services = if peer.v2_transport {
            let mut services = ServiceFlags::P2P_V2;
            services.add(ServiceFlags::NETWORK);
            services.add(ServiceFlags::COMPACT_FILTERS);
            services
        } else {
            let mut services = ServiceFlags::COMPACT_FILTERS;
            services.add(ServiceFlags::NETWORK);
            services
        };
        let addr_v2 = match peer.address.inner {
            IpAddr::V4(ipv4_addr) => AddrV2::Ipv4(ipv4_addr),
            IpAddr::V6(ipv6_addr) => AddrV2::Ipv6(ipv6_addr),
        };
        TrustedPeer::new(addr_v2, peer.port, services)
    }
}

trait DisplayExt {
    fn into_string(self) -> String;
}

impl DisplayExt for RejectReason {
    fn into_string(self) -> String {
        let message = match self {
            RejectReason::Malformed => "Message could not be decoded.",
            RejectReason::Invalid => "Transaction was invalid for some reason.",
            RejectReason::Obsolete => "Client version is no longer supported.",
            RejectReason::Duplicate => "Duplicate version message received.",
            RejectReason::NonStandard => "Transaction was nonstandard.",
            RejectReason::Dust => "One or more outputs are below the dust threshold.",
            RejectReason::Fee => "Transaction does not have enough fee to be mined.",
            RejectReason::Checkpoint => "Inconsistent with compiled checkpoint.",
        };
        message.into()
    }
}

#[cfg(test)]
mod tests {
    use super::{tokio, CbfNode, NodeLifecycle};
    use std::sync::Arc;

    #[test]
    fn progress_uses_the_scan_checkpoint_and_current_header_tip() {
        let mut progress = super::ScanProgress::new(100);
        let _ = progress.map(bdk_kyoto::Info::NewChainHeight(200));
        assert!(matches!(
            progress.map(bdk_kyoto::Info::CFHeadersAdded(150)),
            super::Info::CfHeadersProgress { chain_height: 200, headers_height: 150, fraction } if fraction == 0.5
        ));
        assert!(matches!(
            progress.map(bdk_kyoto::Info::FilterAdded(200)),
            super::Info::FiltersProgress { chain_height: 200, filters_height: 200, fraction } if fraction == 1.0
        ));
        assert_eq!(progress.fraction(99), 0.0);
        assert_eq!(progress.fraction(201), 1.0);
        assert_eq!(super::ScanProgress::new(100).fraction(100), 0.0);
    }

    #[test]
    fn running_a_consumed_node_is_a_no_op() {
        let node = Arc::new(CbfNode {
            lifecycle: Arc::new(NodeLifecycle::new(None)),
        });

        node.run();
    }

    fn public_wallet(branch: u32, lookahead: u32) -> Arc<crate::wallet::Wallet> {
        use crate::{
            bitcoin::NetworkKind, descriptor::Descriptor, store::Persister, wallet::Wallet,
        };
        let descriptors: serde_json::Value =
            serde_json::from_str(include_str!("kyoto/public-descriptors.json")).unwrap();
        let external = descriptors["external"]
            .as_str()
            .unwrap()
            .replace("/0/*", &format!("/{branch}/*"));
        let internal = descriptors["internal"]
            .as_str()
            .unwrap()
            .replace("/1/*", &format!("/{}/*", branch + 1));
        Arc::new(
            Wallet::new(
                Arc::new(Descriptor::new(external, NetworkKind::Main).unwrap()),
                Arc::new(Descriptor::new(internal, NetworkKind::Main).unwrap()),
                super::Network::Bitcoin,
                Arc::new(Persister::new_in_memory().unwrap()),
                lookahead,
            )
            .unwrap(),
        )
    }

    fn checkpoint(height: u32) -> crate::types::BlockId {
        use bdk_wallet::bitcoin::hashes::Hash;
        crate::types::BlockId {
            height,
            hash: Arc::new(crate::bitcoin::BlockHash(
                super::bip157::BlockHash::from_byte_array([height as u8; 32]),
            )),
        }
    }

    #[test]
    fn birthday_checkpoint_and_descriptor_id_are_available_to_multi_wallet_callers() {
        use bdk_wallet::chain::DescriptorExt;
        let wallet = public_wallet(0, 1000);
        let birthday = checkpoint(900_000);
        wallet.insert_checkpoint(birthday.clone()).unwrap();
        assert_eq!(wallet.latest_checkpoint(), birthday);
        assert_eq!(wallet.checkpoints().len(), 2);
        assert_eq!(
            super::sync_start_height(&wallet.get_wallet()),
            birthday.height
        );
        assert_eq!(wallet.get_wallet().spk_index().lookahead(), 1000);
        assert_eq!(
            wallet.descriptor_id(bdk_wallet::KeychainKind::External),
            wallet
                .get_wallet()
                .public_descriptor(bdk_wallet::KeychainKind::External)
                .descriptor_id()
                .to_string()
        );
        assert_ne!(
            wallet.descriptor_id(bdk_wallet::KeychainKind::External),
            wallet.descriptor_id(bdk_wallet::KeychainKind::Internal)
        );
        assert!(wallet.insert_checkpoint(checkpoint(0)).is_err());
        assert_eq!(wallet.latest_checkpoint(), birthday);
        let staged: bdk_wallet::ChangeSet = wallet.take_staged().unwrap().as_ref().clone().into();
        assert!(staged.local_chain.blocks.contains_key(&birthday.height));
    }

    #[test]
    fn multi_wallet_configuration_rejects_empty_duplicates_and_recovery() {
        let builder = super::CbfBuilder::new().only_configured_peers();
        assert!(matches!(
            builder.build_with_wallets(vec![]),
            Err(crate::error::CbfError::InvalidConfiguration { .. })
        ));
        let wallet = public_wallet(0, 1000);
        assert!(matches!(
            builder.build_with_wallets(vec![wallet.clone(), wallet.clone()]),
            Err(crate::error::CbfError::InvalidConfiguration { .. })
        ));
        let duplicate = public_wallet(0, 1000);
        assert!(matches!(
            builder.build_with_wallets(vec![wallet.clone(), duplicate]),
            Err(crate::error::CbfError::InvalidConfiguration { .. })
        ));
        assert!(matches!(
            builder
                .scan_type(super::ScanType::Recovery {
                    used_script_index: 1000,
                    checkpoint: super::RecoveryPoint::SegwitActivation
                })
                .build_with_wallets(vec![wallet]),
            Err(crate::error::CbfError::InvalidConfiguration { .. })
        ));
    }

    #[tokio::test]
    async fn multi_wallet_requests_cancel_safely_and_terminate_without_network() {
        let first = public_wallet(0, 1000);
        let second = public_wallet(2, 1000);
        first.insert_checkpoint(checkpoint(900_000)).unwrap();
        second.insert_checkpoint(checkpoint(903_000)).unwrap();
        let components = super::CbfBuilder::new()
            .only_configured_peers()
            .build_with_wallets(vec![first, second])
            .unwrap();
        assert!(components.client.is_running());
        // These enqueue the real bip157 commands without starting DNS or a peer.
        components.client.rescan_from(901_234).unwrap();
        components.client.rescan().unwrap();
        assert!(matches!(
            components.client.update().await,
            Err(crate::error::CbfError::InvalidConfiguration { .. })
        ));
        // Neither a cancelled wallet receiver nor a cancelled info receiver holds its mutex.
        for _ in 0..2 {
            assert!(super::tokio::time::timeout(
                std::time::Duration::from_millis(5),
                components.client.updates()
            )
            .await
            .is_err());
            assert!(super::tokio::time::timeout(
                std::time::Duration::from_millis(5),
                components.client.next_info()
            )
            .await
            .is_err());
        }
        components.client.shutdown().unwrap();
        assert!(components.node.await_termination(1000).await);
        assert!(!components.client.is_running());
        assert!(matches!(
            components.client.rescan_from(901_234),
            Err(crate::error::CbfError::NodeStopped)
        ));
        assert!(matches!(
            components.client.chain_tip().await,
            Err(crate::error::CbfError::NodeStopped)
        ));
        assert!(matches!(
            components.client.get_header(901_234).await,
            Err(crate::error::CbfError::NodeStopped)
        ));
        assert!(matches!(
            components.client.peer_count().await,
            Err(crate::error::CbfError::NodeStopped)
        ));
        assert!(matches!(
            components.client.updates().await,
            Err(crate::error::CbfError::NodeStopped)
        ));
    }

    #[tokio::test]
    async fn synced_event_is_emitted_after_a_wallet_update_boundary() {
        let wallet = public_wallet(0, 1000);
        let components = super::CbfBuilder::new()
            .only_configured_peers()
            .build(&wallet);
        // Native downloads alone never map to Synced; completion is an update boundary.
        let cp = wallet
            .get_wallet()
            .latest_checkpoint()
            .insert(checkpoint(900_000).into());
        components.client.notify_synced(&bdk_wallet::Update {
            chain: Some(cp),
            ..Default::default()
        });
        assert!(
            matches!(components.client.next_info().await.unwrap(), super::Info::Synced { tip } if tip == checkpoint(900_000))
        );
        components.client.shutdown().unwrap();
        assert!(components.node.await_termination(1000).await);
    }

    #[tokio::test]
    async fn leased_clients_only_expose_callback_free_event_consumption() {
        let wallet = public_wallet(0, 25);
        let builder = super::CbfBuilder::new().only_configured_peers();
        assert!(builder.owner_lease_millis(0).is_err());
        assert!(builder.owner_lease_millis(86_400_001).is_err());
        let leased = builder.owner_lease_millis(1000).unwrap();
        let components = leased.build(&wallet);
        assert!(components.client.legacy.is_none());
        assert!(components.client.poll_updates().unwrap().is_none());
        assert!(components.client.poll_update_batch().unwrap().is_none());
        assert!(components.client.drain_info().unwrap().is_empty());
        assert!(components.client.drain_warnings().unwrap().is_empty());
        assert!(!components.client.status().terminated);
        assert!(matches!(
            components.client.next_info().await,
            Err(crate::error::CbfError::InvalidConfiguration { .. })
        ));
        assert!(matches!(
            components.client.next_warning().await,
            Err(crate::error::CbfError::InvalidConfiguration { .. })
        ));
        assert!(matches!(
            components.client.update().await,
            Err(crate::error::CbfError::InvalidConfiguration { .. })
        ));
        assert!(matches!(
            components.client.updates().await,
            Err(crate::error::CbfError::InvalidConfiguration { .. })
        ));
        components.client.shutdown().unwrap();
        assert!(components.node.is_terminated());
        assert!(components.client.status().terminated);
        assert!(components.client.poll_updates().unwrap().is_none());
        assert!(matches!(
            components.client.renew_lease(),
            Err(crate::error::CbfError::NodeStopped)
        ));
        components.node.clone().run();
        assert!(components.node.is_terminated());
        let legacy = builder.build(&wallet);
        assert!(legacy.client.poll_updates().is_err());
        assert!(legacy.client.poll_update_batch().is_err());
        assert!(legacy.client.drain_info().is_err());
        assert!(legacy.client.drain_warnings().is_err());
        assert!(legacy.client.renew_lease().is_err());
        legacy.client.shutdown().unwrap();
    }

    #[test]
    fn recovery_can_explicitly_resume_the_last_persisted_checkpoint() {
        let wallet = public_wallet(0, 25);
        wallet.insert_checkpoint(checkpoint(900_000)).unwrap();
        wallet.insert_checkpoint(checkpoint(901_000)).unwrap();
        let start =
            super::recovery_checkpoint(&wallet.get_wallet(), super::RecoveryPoint::LastCheckpoint);
        assert_eq!(start.height, 901_000);
        assert_eq!(start.hash, checkpoint(901_000).hash.0);
        // Sparse checkpoints do not rewind an entire recovery interval or to genesis.
        for height in 901_001..=901_010 {
            wallet.insert_checkpoint(checkpoint(height)).unwrap();
        }
        let start =
            super::recovery_checkpoint(&wallet.get_wallet(), super::RecoveryPoint::LastCheckpoint);
        assert_eq!(start.height, 901_003);
        assert_eq!(start.hash, checkpoint(901_003).hash.0);
        // An explicit birthday still requests that exact scan, even after later persistence.
        assert_eq!(
            super::recovery_checkpoint(
                &wallet.get_wallet(),
                super::RecoveryPoint::Other {
                    birthday: checkpoint(900_000)
                }
            )
            .height,
            900_000
        );
        let components = super::CbfBuilder::new()
            .only_configured_peers()
            .owner_lease_millis(1000)
            .unwrap()
            .scan_type(super::ScanType::Recovery {
                used_script_index: 1000,
                checkpoint: super::RecoveryPoint::LastCheckpoint,
            })
            .build(&wallet);
        assert!(components.client.poll_update_batch().unwrap().is_none());
        components.client.shutdown().unwrap();
        assert!(components.node.is_terminated());
    }

    #[test]
    fn leased_shutdown_uses_only_synchronous_native_operations() {
        use std::{
            io::Read,
            net::TcpListener,
            time::{Duration, Instant},
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (connected, accepted) = std::sync::mpsc::channel();
        let peer = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            connected.send(()).unwrap();
            let mut buffer = [0; 4096];
            loop {
                match socket.read(&mut buffer) {
                    Ok(0) => return,
                    Ok(_) => {}
                    Err(error) => panic!("native shutdown must close peer socket: {}", error),
                }
            }
        });
        let wallet = public_wallet(0, 25);
        let components = super::CbfBuilder::new()
            .only_configured_peers()
            .connections(1)
            .configure_timeout_millis(60000, 60000)
            .peers(vec![super::Peer {
                address: std::sync::Arc::new(super::IpAddress::from_ipv4(127, 0, 0, 1)),
                port: Some(port),
                v2_transport: false,
            }])
            .owner_lease_millis(1000)
            .unwrap()
            .build(&wallet);
        components.node.clone().run();
        accepted.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(components.client.legacy.is_none());
        components.client.shutdown().unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        while !components.node.is_terminated() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(!components.client.status().running);
        assert!(components.client.status().terminated);
        peer.join().unwrap();
    }

    #[tokio::test]
    async fn packages_are_validated_before_contacting_the_node() {
        let wallet = public_wallet(0, 1000);
        let components = super::CbfBuilder::new()
            .only_configured_peers()
            .build(&wallet);
        assert!(matches!(
            components.client.submit_package(vec![]).await,
            Err(crate::error::CbfError::InvalidPackage { .. })
        ));
        components.client.shutdown().unwrap();
        assert!(components.node.await_termination(1000).await);
    }
}
