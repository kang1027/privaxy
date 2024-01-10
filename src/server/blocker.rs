use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use adblock::resources::Resource;
use crossbeam_channel::{Receiver, Sender};
use lazy_static::lazy_static;
use tokio::sync::oneshot;
use adblock::blocker::BlockerResult as AdBlockerBlockerResult;
use adblock::engine::Engine;
use adblock::lists::{FilterSet, ParseOptions};
use log::debug;
use include_dir::{Dir, include_dir};
use crate::blocker_utils::{
    build_resource_from_file_contents, read_redirectable_resource_mapping, read_template_resources,
};

pub type AdblockRequestChannel = Sender<BlockerRequest>;

#[derive(Clone, Debug)]
pub struct BlockingDisabledStore(pub Arc<RwLock<bool>>);

impl BlockingDisabledStore {
    pub fn is_enabled(&self) -> bool { !*self.0.read().unwrap()}

    pub fn set(&self, enabled: bool) { *self.0.write().unwrap() = !enabled }
}

pub struct CosmeticRequest {
    pub(crate) url: String,
    pub(crate) ids: Vec<String>,
    pub(crate) classes: Vec<String>,
}

pub struct NetworkUrl {
    url: String,
    referer: String,
}

pub enum RequestKind {
    Url(NetworkUrl),
    Cosmetic(CosmeticRequest),
    ReplaceEngine(Vec<String>),
}

pub enum BlockerResult {
    Network(adblock::blocker::BlockerResult),
    Cosmetic(CosmeticBlockerResult),
}

pub struct CosmeticBlockerResult {
    pub hidden_selectors: Vec<String>,
    pub style_selectors: HashMap<String, Vec<String>>,
    pub injected_script: Option<String>,
}

pub struct BlockerRequest {
    pub(crate) kind: RequestKind,
    pub(crate) respond_to: oneshot::Sender<BlockerResult>,
}

pub struct Blocker {
    pub sender: Sender<BlockerRequest>,
    pub receiver: Receiver<BlockerRequest>,
    engine: Engine,
    blocking_disabled: BlockingDisabledStore,
}

lazy_static! {
    static ref ADBLOCKING_RESOURCES: Vec<Resource> = {
        let mut resources =
            read_template_resources(include_str!("../resources/vendor/ublock/scriptlets.js"));

        static WEB_ACCESSIBLE_RESOURCES: Dir = include_dir!(
            "$CARGO_MANIFEST_DIR/src/resources/vendor/ublock/web_accessible_resources/"
        );

        let resource_properties = read_redirectable_resource_mapping(include_str!(
            "../resources/vendor/ublock/redirect-resources.js"
        ));

        resources.extend(
            resource_properties
                .iter()
                .map(|resource_info| {
                    let resource = WEB_ACCESSIBLE_RESOURCES
                        .get_file(&resource_info.name)
                        .unwrap();
                    build_resource_from_file_contents(resource.contents(), resource_info)
                })
                .collect::<Vec<_>>(),
        );

        resources
    };
}

impl Blocker {
    pub fn new(
        sender: Sender<BlockerRequest>,
        receiver: Receiver<BlockerRequest>,
        blocking_disabled: BlockingDisabledStore,
    ) -> Self {

        Self {
            sender,
            receiver,
            engine: Engine::new(true),
            blocking_disabled,
        }
    }

    pub fn handle_requests(mut self) {
        while let Ok(request) = self.receiver.recv() {
            match request.kind {
                RequestKind::Cosmetic(cosmetic_request) => {
                    if !self.blocking_disabled.is_enabled() {
                        let _result = request.respond_to.send(BlockerResult::Cosmetic(
                            CosmeticBlockerResult {
                                hidden_selectors: Vec::new(),
                                style_selectors: HashMap::new(),
                                injected_script: None,
                            }
                        ));
                        continue;
                    }

                    let mut hidden_selectors = Vec::new();
                    let url_specific_resources = self
                        .engine
                        .url_cosmetic_resources(cosmetic_request.url.as_str());

                    if !url_specific_resources.generichide {
                        let generic_selectors = self.engine.hidden_class_id_selectors(
                            &cosmetic_request.classes,
                            &cosmetic_request.ids,
                            &url_specific_resources.exceptions,
                        );
                        hidden_selectors.extend(generic_selectors);
                    }
                    hidden_selectors.extend(url_specific_resources.hide_selectors.into_iter());

                    let injected_script = if !url_specific_resources.injected_script.is_empty() {
                        Some(url_specific_resources.injected_script)
                    } else {
                        None
                    };

                    let _result = request
                        .respond_to
                        .send(BlockerResult::Cosmetic(CosmeticBlockerResult {
                            hidden_selectors,
                            style_selectors: url_specific_resources.style_selectors,
                            injected_script,
                        }));
                }

                RequestKind::Url(network_url) => {
                    if !self.blocking_disabled.is_enabled() {
                        let _result = request.respond_to.send(BlockerResult::Network(
                            AdBlockerBlockerResult {
                                matched: false,
                                important: false,
                                redirect: None,
                                exception: None,
                                filter: None,
                                error: None,
                                rewritten_url: None,
                            }
                        ));

                        continue;
                    }

                    let blocker_result = self.engine.check_network_urls(
                        network_url.url.as_str(),
                        network_url.referer.as_str(),
                        "other",
                    );

                    let _result = request
                        .respond_to
                        .send(BlockerResult::Network(blocker_result));
                }
                RequestKind::ReplaceEngine(filters) => {
                    debug!("Configuring blocking engine.");

                    let mut filter_set = FilterSet::new(true);

                    for filter in filters {
                        filter_set.add_filter_list(&filter, ParseOptions::default());
                    }

                    let mut adblock_engine = Engine::from_filter_set(filter_set, true);
                    adblock_engine.use_resources(&ADBLOCKING_RESOURCES);

                    self.engine = adblock_engine;
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct AdblockRequester {
    adblock_request_channel: AdblockRequestChannel,
}

impl AdblockRequester {
    pub(crate) fn new(adblock_request_channel: AdblockRequestChannel) -> Self {
        Self {
            adblock_request_channel
        }
    }

    pub(crate) async fn replace_engine(&self, filters: Vec<String>) {
        let (sender, _receiver) = oneshot::channel();

        self.adblock_request_channel
            .send(BlockerRequest {
                respond_to: sender,
                kind: RequestKind::ReplaceEngine(filters),
            })
            .unwrap();
    }

    pub(crate) async fn get_cosmetic_response(
        &self,
        url: String,
        ids: Vec<String>,
        classes: Vec<String>,
    ) -> CosmeticBlockerResult {
        let (sender, receiver) = oneshot::channel();

        self.adblock_request_channel
            .send(BlockerRequest {
                respond_to: sender,
                kind: RequestKind::Cosmetic(CosmeticRequest {url, ids, classes }),
            })
            .unwrap();

        match receiver.await {
            Ok(blocker_result) => match blocker_result {
                BlockerResult::Cosmetic(blocker_result) => blocker_result,
                BlockerResult::Network(_) => unreachable!(),
            },
            Err(_err) => unreachable!(),
        }
    }

    pub(crate) async fn is_network_url_blocked(
        &self,
        network_url: String,
        referer: String,
    ) -> (bool, AdBlockerBlockerResult) {
        let (sender, receiver) = oneshot::channel();

        self.adblock_request_channel
            .send(BlockerRequest {
                respond_to: sender,
                kind: RequestKind::Url(NetworkUrl {
                    url: network_url,
                    referer,
                }),
            })
            .unwrap();

        match receiver.await {
            Ok(blocker_result) => match blocker_result {
                BlockerResult::Network(blocker_result) => {
                    (blocker_result.matched, blocker_result)
                }
                BlockerResult::Cosmetic(_) => unreachable!(),
            },
            Err(_err) => unreachable!(),
        }
    }
}

