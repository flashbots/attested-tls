use std::{sync::mpsc, thread};

use attestation::AttestationGeneratorClient;
use attestation_provider_server::{
    AttestationGenerator,
    ProviderSocket,
    attestation_provider_server,
};
use tokio::sync::oneshot;

pub(crate) struct MockQuoteProvider {
    pub(crate) client: AttestationGeneratorClient,
    shutdown: Option<oneshot::Sender<()>>,
    worker: Option<thread::JoinHandle<()>>,
}

impl MockQuoteProvider {
    pub(crate) fn start() -> Self {
        let (ready, bound) = mpsc::sync_channel(1);
        let (shutdown, stop) = oneshot::channel();
        // Certificate issuance can block the caller's Tokio runtime.
        let worker = thread::spawn(move || {
            let runtime =
                tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            runtime.block_on(async {
                let dir = tempfile::tempdir().unwrap();
                let path = dir.path().join("provider.sock");
                let socket = ProviderSocket::bind(&path).unwrap();
                ready.send(AttestationGeneratorClient::new(path).unwrap()).unwrap();

                tokio::select! {
                    result = attestation_provider_server(&socket.listener, AttestationGenerator::mock()) => result.unwrap(),
                    _ = stop => {}
                }
            });
        });
        Self { client: bound.recv().unwrap(), shutdown: Some(shutdown), worker: Some(worker) }
    }
}

impl Drop for MockQuoteProvider {
    fn drop(&mut self) {
        let _ = self.shutdown.take().unwrap().send(());
        let result = self.worker.take().unwrap().join();
        if !thread::panicking() {
            result.unwrap();
        }
    }
}
