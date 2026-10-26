use crate::bitcoin::{BlockHash, Transaction, Txid};
use crate::descriptor::Descriptor;
use crate::electrum::ElectrumClient;
use crate::store::Persister;
use crate::types::{BlockId, ConfirmationBlockTime, TxAnchor};
use crate::wallet::Wallet;

use bdk_wallet::bitcoin::absolute::LockTime;
use bdk_wallet::bitcoin::block::{Header, Version as BlockVersion};
use bdk_wallet::bitcoin::consensus::encode::{serialize, serialize_hex};
use bdk_wallet::bitcoin::hashes::{sha256, sha256d, Hash};
use bdk_wallet::bitcoin::hex::DisplayHex;
use bdk_wallet::bitcoin::transaction::Version;
use bdk_wallet::bitcoin::{
    constants, Amount, BlockHash as BdkBlockHash, CompactTarget, Network, OutPoint, ScriptBuf,
    Sequence, Transaction as BdkTransaction, TxIn, TxMerkleNode, TxOut, Txid as BdkTxid, Witness,
};
use bdk_wallet::KeychainKind;
use serde_json::{json, Value};

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;

const EXTERNAL_DESCRIPTOR: &str = "wpkh(tprv8ZgxMBicQKsPf2qfrEygW6fdYseJDDrVnDv26PH5BHdvSuG6ecCbHqLVof9yZcMoM31z9ur3tTYbSnr1WBqbGX97CbXcmp5H6qeMpyvx35B/84h/1h/1h/0/*)";
const INTERNAL_DESCRIPTOR: &str = "wpkh(tprv8ZgxMBicQKsPf2qfrEygW6fdYseJDDrVnDv26PH5BHdvSuG6ecCbHqLVof9yZcMoM31z9ur3tTYbSnr1WBqbGX97CbXcmp5H6qeMpyvx35B/84h/1h/1h/1/*)";
const BLOCK_TIME: u32 = 1_296_688_602 + 600;

/// Loopback Electrum server: genesis plus one block holding `tx`, and a per-method call count.
struct Fixture {
    url: String,
    tx: BdkTransaction,
    headers: Vec<Header>,
    calls: Arc<Mutex<HashMap<String, usize>>>,
}

impl Fixture {
    fn start(spk: ScriptBuf) -> Self {
        let tx = BdkTransaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(BdkTxid::all_zeros(), 0),
                script_sig: ScriptBuf::from(vec![0x51]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: spk.clone(),
            }],
        };
        let genesis = constants::genesis_block(Network::Regtest).header;
        let block = Header {
            version: BlockVersion::ONE,
            prev_blockhash: genesis.block_hash(),
            merkle_root: TxMerkleNode::from_raw_hash(tx.compute_txid().to_raw_hash()),
            time: BLOCK_TIME,
            bits: CompactTarget::from_consensus(0x207fffff),
            nonce: 1,
        };
        let headers = vec![genesis, block];
        let mut script_hash = sha256::Hash::hash(spk.as_bytes()).to_byte_array();
        script_hash.reverse();
        let script_hash = script_hash.to_lower_hex_string();
        let calls = Arc::new(Mutex::new(HashMap::new()));

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("tcp://{}", listener.local_addr().unwrap());
        let (served_tx, served_headers, counts) = (tx.clone(), headers.clone(), calls.clone());
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                let (tx, headers, counts) =
                    (served_tx.clone(), served_headers.clone(), counts.clone());
                let script_hash = script_hash.clone();
                thread::spawn(move || {
                    let mut writer = stream.try_clone().unwrap();
                    for line in BufReader::new(stream).lines() {
                        let Ok(line) = line else { break };
                        let Ok(request) = serde_json::from_str::<Value>(&line) else {
                            break;
                        };
                        let answer = |r: &Value| answer(r, &tx, &headers, &script_hash, &counts);
                        let response = match request {
                            Value::Array(batch) => Value::Array(batch.iter().map(answer).collect()),
                            single => answer(&single),
                        };
                        if writeln!(writer, "{response}").is_err() {
                            break;
                        }
                    }
                });
            }
        });
        Fixture {
            url,
            tx,
            headers,
            calls,
        }
    }

    fn client(&self) -> ElectrumClient {
        ElectrumClient::new(self.url.clone(), None, Some(5), Some(0), false).unwrap()
    }

    fn txid(&self) -> Arc<Txid> {
        Arc::new(Txid(self.tx.compute_txid()))
    }

    fn block_hash(&self) -> BdkBlockHash {
        self.headers[1].block_hash()
    }

    fn calls(&self, method: &str) -> usize {
        *self.calls.lock().unwrap().get(method).unwrap_or(&0)
    }

    fn reset_calls(&self) {
        self.calls.lock().unwrap().clear();
    }
}

fn answer(
    request: &Value,
    tx: &BdkTransaction,
    headers: &[Header],
    script_hash: &str,
    calls: &Mutex<HashMap<String, usize>>,
) -> Value {
    let id = request["id"].clone();
    let method = request["method"].as_str().unwrap_or_default();
    let params = request["params"].as_array().cloned().unwrap_or_default();
    *calls.lock().unwrap().entry(method.to_string()).or_default() += 1;
    let tip = headers.len() - 1;
    let result = match method {
        "server.version" => json!(["fixture", "1.4"]),
        "server.ping" => Value::Null,
        "blockchain.headers.subscribe" => {
            json!({"height": tip, "hex": serialize_hex(&headers[tip])})
        }
        "blockchain.block.header" => json!(serialize_hex(
            &headers[params[0].as_u64().unwrap() as usize]
        )),
        "blockchain.block.headers" => {
            let start = params[0].as_u64().unwrap() as usize;
            let count = params[1].as_u64().unwrap() as usize;
            let hex: String = headers
                .iter()
                .skip(start)
                .take(count)
                .map(serialize_hex)
                .collect();
            json!({"count": hex.len() / 160, "hex": hex, "max": 2016})
        }
        "blockchain.scripthash.get_history" => {
            if params[0].as_str() == Some(script_hash) {
                json!([{"tx_hash": tx.compute_txid().to_string(), "height": 1}])
            } else {
                json!([])
            }
        }
        "blockchain.transaction.get" => json!(serialize(tx).to_lower_hex_string()),
        "blockchain.transaction.get_merkle" => json!({"block_height": 1, "merkle": [], "pos": 0}),
        other => {
            return json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": other}})
        }
    };
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn new_wallet() -> (Wallet, ScriptBuf) {
    let wallet = Wallet::new(
        Arc::new(
            Descriptor::new(
                EXTERNAL_DESCRIPTOR.to_string(),
                crate::bitcoin::NetworkKind::Test,
            )
            .unwrap(),
        ),
        Arc::new(
            Descriptor::new(
                INTERNAL_DESCRIPTOR.to_string(),
                crate::bitcoin::NetworkKind::Test,
            )
            .unwrap(),
        ),
        crate::bitcoin::Network::Regtest,
        Arc::new(Persister::new_in_memory().unwrap()),
        25,
    )
    .unwrap();
    let spk = wallet
        .reveal_next_address(KeychainKind::External)
        .address
        .0
        .script_pubkey();
    (wallet, spk)
}

fn wallet_and_fixture() -> (Wallet, Fixture) {
    let (wallet, spk) = new_wallet();
    (wallet, Fixture::start(spk))
}

fn sync(wallet: &Wallet, client: &ElectrumClient) {
    let request = wallet.start_sync_with_revealed_spks().build().unwrap();
    let update = client.sync(request, 10, false).unwrap();
    wallet.apply_update(update).unwrap();
}

fn anchor(fixture: &Fixture, hash: BdkBlockHash) -> TxAnchor {
    TxAnchor {
        txid: fixture.txid(),
        anchor: ConfirmationBlockTime {
            block_id: BlockId {
                height: 1,
                hash: Arc::new(BlockHash(hash)),
            },
            confirmation_time: BLOCK_TIME as u64,
        },
    }
}

#[test]
fn test_populate_tx_cache_skips_transaction_download() {
    let (_, fixture) = wallet_and_fixture();

    let cold = fixture.client();
    cold.fetch_tx(fixture.txid()).unwrap();
    assert_eq!(fixture.calls("blockchain.transaction.get"), 1);

    fixture.reset_calls();
    let warm = fixture.client();
    let tx = Arc::new(Transaction::new(serialize(&fixture.tx)).unwrap());
    warm.populate_tx_cache(vec![tx]);
    let fetched = warm.fetch_tx(fixture.txid()).unwrap();
    assert_eq!(
        fetched.compute_txid().to_string(),
        fixture.txid().to_string()
    );
    assert_eq!(fixture.calls("blockchain.transaction.get"), 0);
}

#[test]
fn test_sync_with_prefilled_caches_skips_tx_and_proof_downloads() {
    let (wallet, fixture) = wallet_and_fixture();
    sync(&wallet, &fixture.client());
    assert_eq!(fixture.calls("blockchain.transaction.get"), 1);
    assert_eq!(fixture.calls("blockchain.transaction.get_merkle"), 1);
    assert_eq!(wallet.balance().confirmed.to_sat(), 100_000);

    fixture.reset_calls();
    // Same descriptors as the first wallet, so it watches the same script.
    let (prefilled, _) = new_wallet();
    let client = fixture.client();
    client.populate_tx_cache(vec![Arc::new(
        Transaction::new(serialize(&fixture.tx)).unwrap(),
    )]);
    client.populate_anchor_cache(vec![anchor(&fixture, fixture.block_hash())]);
    let request = prefilled.start_sync_with_revealed_spks().build().unwrap();
    let update = client.sync(request, 10, false).unwrap();
    prefilled.apply_update(update).unwrap();
    assert_eq!(fixture.calls("blockchain.transaction.get"), 0);
    assert_eq!(fixture.calls("blockchain.transaction.get_merkle"), 0);
    assert_eq!(prefilled.balance().confirmed.to_sat(), 100_000);
}

#[test]
fn test_anchor_for_another_block_is_not_reused() {
    let (wallet, fixture) = wallet_and_fixture();
    let client = fixture.client();
    let orphan = BdkBlockHash::from_byte_array(sha256d::Hash::hash(b"orphan").to_byte_array());
    client.populate_anchor_cache(vec![anchor(&fixture, orphan)]);
    sync(&wallet, &client);
    assert_eq!(fixture.calls("blockchain.transaction.get_merkle"), 1);
    let canonical = wallet.get_tx(fixture.txid()).unwrap().unwrap();
    match canonical.chain_position {
        crate::types::ChainPosition::Confirmed {
            confirmation_block_time,
            ..
        } => assert_eq!(
            confirmation_block_time.block_id.hash.to_string(),
            fixture.block_hash().to_string()
        ),
        _ => panic!("expected a confirmed transaction"),
    }
}
