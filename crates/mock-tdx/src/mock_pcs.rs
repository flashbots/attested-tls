use std::{
    collections::HashMap as StdHashMap,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use axum::{
    Json,
    Router,
    extract::{Query, State},
    response::IntoResponse,
    routing::get,
};
use dcap_qvl::QuoteCollateralV3;
use serde_json::{Value, json};
use tokio::{net::TcpListener, task::JoinHandle};

use crate::mock_collateral;

/// Configuration for a mock PCS server backed by `mock-tdx` collateral
#[derive(Clone)]
pub struct MockPcsConfig {
    /// Whether the `/fmspcs` endpoint should advertise the mock FMSPC
    pub include_fmspcs_listing: bool,
    /// `nextUpdate` value returned by the first TCB info response
    pub tcb_next_update: String,
    /// `nextUpdate` value returned by the first QE identity response
    pub qe_next_update: String,
    /// Optional `nextUpdate` value returned by later TCB info responses
    pub refreshed_tcb_next_update: Option<String>,
    /// Optional `nextUpdate` value returned by later QE identity responses
    pub refreshed_qe_next_update: Option<String>,
}

impl Default for MockPcsConfig {
    /// Builds a fixture-consistent config from the embedded mock collateral
    fn default() -> Self {
        let collateral = mock_collateral();
        let tcb_info: Value = serde_json::from_str(&collateral.tcb_info).unwrap();
        let qe_identity: Value = serde_json::from_str(&collateral.qe_identity).unwrap();

        Self {
            include_fmspcs_listing: true,
            tcb_next_update: tcb_info["nextUpdate"].as_str().unwrap().to_string(),
            qe_next_update: qe_identity["nextUpdate"].as_str().unwrap().to_string(),
            refreshed_tcb_next_update: None,
            refreshed_qe_next_update: None,
        }
    }
}

/// Handle to a running mock PCS server
pub struct MockPcsServer {
    /// Base URL for the spawned server
    pub base_url: String,
    _task: JoinHandle<()>,
    tcb_calls: Arc<AtomicUsize>,
    qe_calls: Arc<AtomicUsize>,
}

impl Drop for MockPcsServer {
    fn drop(&mut self) {
        self._task.abort();
    }
}

impl MockPcsServer {
    /// Returns how many times the TCB info endpoint has been called
    pub fn tcb_call_count(&self) -> usize {
        self.tcb_calls.load(Ordering::SeqCst)
    }

    /// Returns how many times the QE identity endpoint has been called
    pub fn qe_call_count(&self) -> usize {
        self.qe_calls.load(Ordering::SeqCst)
    }
}

/// Shared state served by the mock PCS routes
#[derive(Clone)]
struct MockPcsState {
    fmspc: String,
    include_fmspcs_listing: bool,
    base_tcb_info: Value,
    base_qe_identity: Value,
    tcb_signature_hex: String,
    qe_signature_hex: String,
    tcb_next_update: String,
    qe_next_update: String,
    refreshed_tcb_next_update: Option<String>,
    refreshed_qe_next_update: Option<String>,
    pck_crl: Vec<u8>,
    pck_crl_issuer_chain: String,
    tcb_issuer_chain: String,
    qe_issuer_chain: String,
    root_ca_crl_hex: String,
    tcb_calls: Arc<AtomicUsize>,
    qe_calls: Arc<AtomicUsize>,
}

/// Spawns a local mock PCS server using the embedded `mock-tdx` collateral
pub async fn spawn_mock_pcs_server(
    config: MockPcsConfig,
) -> Result<MockPcsServer, Box<dyn std::error::Error>> {
    let base_collateral: QuoteCollateralV3 = mock_collateral();

    let mut tcb_info: Value = serde_json::from_str(&base_collateral.tcb_info)?;
    tcb_info["nextUpdate"] = Value::String(config.tcb_next_update.clone());

    let mut qe_identity: Value = serde_json::from_str(&base_collateral.qe_identity)?;
    qe_identity["nextUpdate"] = Value::String(config.qe_next_update.clone());

    let tcb_calls = Arc::new(AtomicUsize::new(0));
    let qe_calls = Arc::new(AtomicUsize::new(0));
    let state = Arc::new(MockPcsState {
        fmspc: tcb_info["fmspc"].as_str().ok_or("mock collateral missing fmspc")?.to_string(),
        include_fmspcs_listing: config.include_fmspcs_listing,
        base_tcb_info: tcb_info,
        base_qe_identity: qe_identity,
        tcb_signature_hex: hex::encode(&base_collateral.tcb_info_signature),
        qe_signature_hex: hex::encode(&base_collateral.qe_identity_signature),
        tcb_next_update: config.tcb_next_update,
        qe_next_update: config.qe_next_update,
        refreshed_tcb_next_update: config.refreshed_tcb_next_update,
        refreshed_qe_next_update: config.refreshed_qe_next_update,
        pck_crl: base_collateral.pck_crl,
        pck_crl_issuer_chain: urlencoding::encode(&base_collateral.pck_crl_issuer_chain).into(),
        tcb_issuer_chain: urlencoding::encode(&base_collateral.tcb_info_issuer_chain).into(),
        qe_issuer_chain: urlencoding::encode(&base_collateral.qe_identity_issuer_chain).into(),
        root_ca_crl_hex: hex::encode(base_collateral.root_ca_crl),
        tcb_calls: tcb_calls.clone(),
        qe_calls: qe_calls.clone(),
    });

    let app = Router::new()
        .route("/sgx/certification/v4/fmspcs", get(mock_fmspcs_handler))
        .route("/sgx/certification/v4/pckcrl", get(mock_pck_crl_handler))
        .route("/tdx/certification/v4/tcb", get(mock_tcb_handler))
        .route("/tdx/certification/v4/qe/identity", get(mock_qe_identity_handler))
        .route("/sgx/certification/v4/rootcacrl", get(mock_root_ca_crl_handler))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr: SocketAddr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    Ok(MockPcsServer { base_url: format!("http://{addr}"), _task: task, tcb_calls, qe_calls })
}

/// Serves the mock PCK CRL and issuer chain
async fn mock_pck_crl_handler(
    State(state): State<Arc<MockPcsState>>,
    Query(params): Query<StdHashMap<String, String>>,
) -> impl IntoResponse {
    assert!(
        matches!(params.get("ca").map(String::as_str), Some("processor") | Some("platform")),
        "unexpected ca query value for pckcrl"
    );
    assert_eq!(params.get("encoding"), Some(&"der".to_string()));
    ([("SGX-PCK-CRL-Issuer-Chain", state.pck_crl_issuer_chain.clone())], state.pck_crl.clone())
}

/// Serves the optional FMSPC listing used by PCCS prewarm tests
async fn mock_fmspcs_handler(State(state): State<Arc<MockPcsState>>) -> impl IntoResponse {
    if state.include_fmspcs_listing {
        Json(json!([{
            "fmspc": state.fmspc,
            "platform": "all",
        }]))
    } else {
        Json(json!([]))
    }
}

/// Serves signed TCB info with configurable refresh behavior
async fn mock_tcb_handler(
    State(state): State<Arc<MockPcsState>>,
    Query(params): Query<StdHashMap<String, String>>,
) -> impl IntoResponse {
    assert_eq!(params.get("fmspc"), Some(&state.fmspc));
    let call_number = state.tcb_calls.fetch_add(1, Ordering::SeqCst) + 1;
    let mut tcb_info = state.base_tcb_info.clone();
    let next_update = if call_number == 1 {
        state.tcb_next_update.clone()
    } else {
        state.refreshed_tcb_next_update.clone().unwrap_or_else(|| state.tcb_next_update.clone())
    };
    tcb_info["nextUpdate"] = Value::String(next_update);
    (
        [("SGX-TCB-Info-Issuer-Chain", state.tcb_issuer_chain.clone())],
        Json(json!({
            "tcbInfo": tcb_info,
            "signature": state.tcb_signature_hex,
        })),
    )
}

/// Serves signed QE identity collateral with configurable refresh behavior
async fn mock_qe_identity_handler(
    State(state): State<Arc<MockPcsState>>,
    Query(params): Query<StdHashMap<String, String>>,
) -> impl IntoResponse {
    assert_eq!(params.get("update"), Some(&"standard".to_string()));
    let call_number = state.qe_calls.fetch_add(1, Ordering::SeqCst) + 1;
    let mut qe_identity = state.base_qe_identity.clone();
    let next_update = if call_number == 1 {
        state.qe_next_update.clone()
    } else {
        state.refreshed_qe_next_update.clone().unwrap_or_else(|| state.qe_next_update.clone())
    };
    qe_identity["nextUpdate"] = Value::String(next_update);
    (
        [("SGX-Enclave-Identity-Issuer-Chain", state.qe_issuer_chain.clone())],
        Json(json!({
            "enclaveIdentity": qe_identity,
            "signature": state.qe_signature_hex,
        })),
    )
}

/// Serves the root CA CRL expected by the PCS client
async fn mock_root_ca_crl_handler(State(state): State<Arc<MockPcsState>>) -> impl IntoResponse {
    state.root_ca_crl_hex.clone()
}
