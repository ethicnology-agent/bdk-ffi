mod lifecycle;

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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;

use crate::bitcoin::BlockHash;
use crate::bitcoin::Transaction;
use crate::bitcoin::Wtxid;
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
    info_rx: Mutex<(Receiver<bdk_kyoto::Info>, ScanProgress)>,
    warning_rx: Mutex<Receiver<bdk_kyoto::Warning>>,
    update_rx: Mutex<UpdateSubscriber<bdk_kyoto::wallets::Single>>,
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
    /// Start the node on its owned OS thread and immediately return.
    /// Subsequent calls have no effect.
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
        }
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
            ScanType::Recovery { checkpoint, .. } => Some(match checkpoint {
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
                RecoveryPoint::Other { birthday } => {
                    HashCheckpoint::new(birthday.height, birthday.hash.0)
                }
            }),
        };
        // Match the upstream routine-sync rewind over checkpoint entries.
        let start_height = recovery_checkpoint.map(|cp| cp.height).unwrap_or_else(|| {
            wallet
                .latest_checkpoint()
                .iter()
                .take(8)
                .last()
                .unwrap()
                .height()
        });

        let mut builder = BDKCbfBuilder::new(wallet.network())
            .required_peers(self.connections)
            .handshake_timeout(self.handshake_timeout)
            .response_timeout(self.response_timeout)
            .add_peers(trusted_peers);

        if let Some(proxy) = &self.socks5_proxy {
            let port = proxy.port;
            let addr = proxy.address.inner;
            builder = builder.socks5_proxy(SocketAddr::new(addr, port));
        }

        if self.whitelist_only {
            builder = builder.whitelist_only();
        }

        let client = match self.scan_type {
            ScanType::Sync => builder.build_with_wallet(
                &wallet,
                bdk_kyoto::SyncConfig::sync_from_last_checkpoint().build(),
            ),
            ScanType::Recovery {
                used_script_index, ..
            } => builder.build_with_wallet(
                &wallet,
                bdk_kyoto::SyncConfig::wallet_recovery_sync(
                    recovery_checkpoint.expect("recovery checkpoint was resolved"),
                    used_script_index,
                )
                .build(),
            ),
        }
        .expect("networks match by definition");
        let (client, logging, update_subscriber) = client.subscribe();
        let (client, node) = client.managed_start();
        let requester = client.requester();

        let lifecycle = Arc::new(NodeLifecycle::new(Some(node)));
        let node = CbfNode {
            lifecycle: lifecycle.clone(),
        };

        let client = CbfClient {
            sender: Arc::new(requester),
            lifecycle,
            info_rx: Mutex::new((logging.info_subscriber, ScanProgress::new(start_height))),
            warning_rx: Mutex::new(logging.warning_subscriber),
            update_rx: Mutex::new(update_subscriber),
        };

        CbfComponents {
            client: Arc::new(client),
            node: Arc::new(node),
        }
    }
}

#[uniffi::export]
impl CbfClient {
    /// Return the next available info message from a node. If none is returned, the node has stopped.
    pub async fn next_info(&self) -> Result<Info, CbfError> {
        let mut info = self.info_rx.lock().await;
        let value = info.0.recv().await.ok_or(CbfError::NodeStopped)?;
        Ok(info.1.map(value))
    }

    /// Return the next available warning message from a node. If none is returned, the node has stopped.
    pub async fn next_warning(&self) -> Result<Warning, CbfError> {
        let mut warn_rx = self.warning_rx.lock().await;
        warn_rx
            .recv()
            .await
            .map(|warn| warn.into())
            .ok_or(CbfError::NodeStopped)
    }

    /// Return an [`Update`]. This is method returns once the node syncs to the rest of
    /// the network or a new block has been gossiped.
    pub async fn update(&self) -> Result<Update, CbfError> {
        let update = self
            .update_rx
            .lock()
            .await
            .update()
            .await
            .map_err(|_| CbfError::NodeStopped)?;
        Ok(Update(update))
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
    use super::{CbfNode, NodeLifecycle};
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
}
