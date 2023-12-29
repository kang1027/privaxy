use std::sync::Arc;
use log::{debug, error};
use reqwest::redirect::Policy;
use crate::proxy::exclusion::LocalExclusionStore;
use crate::blocker::BlockingDisabledStore;
use tokio::sync::mpsc;
use tokio::sync::broadcast;
use crate::events::Event;

pub mod configuration;
mod ca;
mod proxy;
mod blocker;
mod statistics;
mod events;
mod cert;

#[derive(Debug)]
pub struct PrivaxyServer {
    pub certificate_pem: String,
    pub configuration_updater_sender: mpsc::Sender<configuration::Configuration>,
    pub configuration_save_lock: Arc<tokio::sync::Mutex<()>>,
    pub blocking_disabled_store: blocker::BlockingDisabledStore,
    pub statistics: statistics::Statistics,
    pub local_exclusion_store: LocalExclusionStore,
    pub requests_broadcast_sender: broadcast::Sender<Event>
}

pub async fn start_privaxy() {
    // let ip = [127, 0, 0, 1];
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .redirect(Policy::none())
        .no_proxy()
        .gzip(true)
        .brotli(true)
        .deflate(true)
        .build()
        .unwrap();

    let configuration = match configuration::Configuration::read_from_home(client.clone()).await {
        Ok(configuration) => configuration,
        Err(err) => {
            error!("An error occured while trying to process the configuration file : {:?}", err);
            std::process::exit(1)
        }
    };

    let local_exclusion_store_clone = LocalExclusionStore::new(configuration.get_exclusion().unwrap()).clone();

    let (ca_certificate, ca_private_key) = configuration.get_certificate().unwrap();
    let certificate_pem = std::str::from_utf8(&ca_certificate.to_pem().unwrap())
        .unwrap()
        .to_string();

    let cert_cache = cert::CertCache::new(ca_certificate, ca_private_key);

    let statistics = statistics::Statistics::new();
    let statistics_clone = statistics.clone();

    let (broadcast_tx, _broadcast_rx) = broadcast::channel(32);
    let broadcast_tx_clone = broadcast_tx.clone();



}
