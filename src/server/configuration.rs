use crate::{ca::make_ca_certificate};
use std::collections::BTreeSet;
use std::io::{Error, ErrorKind};
use tokio::{fs, spawn};
use std::path::{PathBuf};
use std::sync::mpsc::Receiver;
use std::time::Duration;
use futures::future::{Abortable, AbortHandle, try_join_all};
use log::{debug, error, info};
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use reqwest::{Client, Url};
use thiserror::Error;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::{channel, Sender};
use tokio::time::sleep;
use url::Url;
use crate::blocker::AdblockRequester;

// Configuration 메서드 결과 관리 위한 type 지정
type ConfigurationResult<T> = Result<T,ConfigurationError>;

const BASE_FILTERS_URL: &str = "https://filters.privaxy.net";
const METADATA_FILE_NAME: &str = "metadata.json";
const CONFIGURATION_DIRECTORY_NAME: &str = ".privaxy";
const CONFIGURATION_FILE_NAME: &str = "config";
const FILTERS_DIRECTORY_NAME: &str = "filters";
const FILTERS_UPDATE_AFTER: Duration = Duration::from_secs(60 * 10);

// error 관리 위해 thiserror crate 사용.
// Configuration 의 Error 타입을 사용자 정의 지정.
#[derive(Error, Debug)]
pub enum ConfigurationError {
    #[error("file system error")]
    FileSystemError(#[from] std::io::Error),
    #[error("this user home directory not found")]
    HomeDirectoryNotFound,
    #[error("unable store disconnected")]
    UnableToRetrieveDefaultFilters(#[from] reqwest::Error)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Configuration {
    // proxy 처리하지 않을 호스트들
    exclusions: BTreeSet<String>,
    // 사용자 지정 필터
    custom_filter: Vec<String>,
    // 인증기관(Certification Authority) 인증서
    ca: Ca,
    // 적용중인 필터들(?)
    filters: Vec<Filter>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Ca {
    // 인증서
    ca_certificate: String,
    // 비밀키
    ca_private_key: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Filter {
    // 적용 여부
    enabled: bool,
    // 필터 이름
    file_name: String,
    // 필터 그룹
    group: FilterGroup,
    // 필터 제목
    title: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
enum FilterGroup {
    Default,
    Regional,
    Ads,
    Privacy,
    Malware,
    Social,
}

// https://filters.privaxy.net/metadata.json 에서 스크레핑하기 위한 구조체
// privaxy 에서 사전에 지정한 DefaultFilter List 임.
#[derive(Deserialize)]
pub struct DefaultFilter {
    enabled_by_default: bool,
    file_name: String,
    group: String,
    title: String,
}

impl Filter {
    async fn update(&self, http_client: &Client) -> ConfigurationResult<String> {
        debug!("Updating filter: {}", self.title);

        let home_directory = get_home_directory()?;
        let configuration_directory = home_directory.join(CONFIGURATION_DIRECTORY_NAME);
        let filters_directory = configuration_directory.join(FILTERS_DIRECTORY_NAME);

        fs::create_dir(&filters_directory).await?;

        let filter = get_filter(&self.file_name, http_client).await?;

        fs::write(filters_directory.join(&self.file_name), &filter).await?;

        Ok(filter)
    }

    pub async fn get_contents(&self, http_client: &Client) -> ConfigurationResult<String> {
        let filter_path = get_home_directory()?
            .join(CONFIGURATION_DIRECTORY_NAME)
            .join(FILTERS_DIRECTORY_NAME)
            .join(&self.file_name);

        match fs::read(filter_path).await {
            Err(err) => {
                if err.kind() == ErrorKind::NotFound {
                    self.update(http_client).await
                }
                Err(ConfigurationError::FileSystemError(err))
            }
            Ok(filter) => Ok(std::str::from_utf8(&filter)?.to_string()),
        }
    }
}

// DefaultFilter -> Filter 매핑 trait 구현체
impl From<DefaultFilter> for Filter {
    fn from(default_filter: DefaultFilter) -> Self {
        Self {
            enabled: default_filter.enabled_by_default,
            title: default_filter.title,
            group: match default_filter.group.as_str() {
                "default" => FilterGroup::Default,
                "regional" => FilterGroup::Regional,
                "ads" => FilterGroup::Ads,
                "privacy" => FilterGroup::Privacy,
                "malware" => FilterGroup::Malware,
                "social" => FilterGroup::Social,
                _ => unreachable!(),
            },
            file_name: default_filter.file_name,
        }
    }
}

impl Configuration {
    pub async fn read_from_home(client: Client) -> ConfigurationResult<Self>{

        let home_dir = get_home_directory()?;
        let configuration_directory = home_dir.join(CONFIGURATION_DIRECTORY_NAME);
        let configuration_file_path = configuration_directory.join(CONFIGURATION_FILE_NAME);

        // .privaxy directory 가 없을 시 .privaxy directory 와 config 파일 생성
        if let Err(err) = fs::metadata(&configuration_directory).await {
            let configuration = Self::create_dir_if_not_found(&configuration_directory, client, err).await?;
            return Ok(configuration);
        }

        // config file 이 없을 때, config file 생성.
        return match fs::read(&configuration_file_path).await {
            Ok(bytes) => Ok(toml::from_str(&String::from_utf8_lossy(&bytes)).unwrap()),
            Err(err) => Ok(Self::create_config_file_if_not_found(client, err).await?)
        }
    }

    async fn create_config_file_if_not_found(client: Client, err: Error) -> ConfigurationResult<Self> {
        if err.kind() == std::io::ErrorKind::NotFound {
            debug!("Configuration file not found, creating one");

            let configuration = Self::new_default(client).await?;
            configuration.save_to_config_file().await?;
            return Ok(configuration)
        }
        Err(ConfigurationError::FileSystemError(err))
    }

    async fn create_dir_if_not_found(dir: &PathBuf, client: Client, err: Error) -> ConfigurationResult<Self> {
        if err.kind() == std::io::ErrorKind::NotFound {
            debug!("Configuration directory not found, creating one");
            return match fs::create_dir(dir).await {
                Ok(_) => {
                    // default configuration 설정
                    let configuration = Self::new_default(client).await?;
                    configuration.save_to_config_file().await?;
                    Ok(configuration)
                }
                Err(err) => Err(ConfigurationError::FileSystemError(err))
            }
        }
        Err(ConfigurationError::FileSystemError(err))
    }

    async fn new_default(client: Client) -> ConfigurationResult<Self>{
        let default_filters = Self::get_default_filters(client).await?;

        // X.509 인증서와 private key 생성
        let (x509, private_key) = make_ca_certificate();

        // X.509 인증서를 pem 으로 변환
        // 데이터를 텍스트로 쉽게 표시하고 전송하기 위해 pem(Privacy Enhanced Mail) 으로 변환함.
        // 텍스트 에디터에서 열람 가능, 텍스트 기반 프로토콜 도구와 호환성 높음
        let x509_pem = std::str::from_utf8(&x509.to_pem().unwrap())
            .unwrap()
            .to_string();

        // private key 도 pem 으로 변환
        let private_key_pem = std::str::from_utf8(&private_key.private_key_to_pem_pkcs8().unwrap())
            .unwrap()
            .to_string();

        Ok(
            Configuration {
                exclusions: BTreeSet::new(),
                custom_filter: Vec::new(),
                ca: Ca {
                    ca_certificate: x509_pem,
                    ca_private_key: private_key_pem,
                },
                filters: default_filters
                    .into_iter()
                    .map(|filter| filter.into())
                    .collect(),
            })
    }

    async fn save_to_config_file(&self) -> ConfigurationResult<()> {
        let home_directory = get_home_directory()?;
        // home_dir/.privaxy/config
        let configuration_file_path = home_directory.join(CONFIGURATION_DIRECTORY_NAME).join(CONFIGURATION_FILE_NAME);

        let configuration_serialized = toml::to_string_pretty(&self).unwrap();
        fs::write(configuration_file_path, configuration_serialized).await?;

        Ok(())
    }

    async fn get_default_filters(client: Client) -> ConfigurationResult<Vec<DefaultFilter>> {
        let url = BASE_FILTERS_URL.parse::<Url>().unwrap();
        let filters_url = url.join(METADATA_FILE_NAME).unwrap();
        // https://filters.privaxy.net/metadata.json 에서 스크레핑해 DefaultFilter 에 매핑.
        let response = client.get(filters_url.as_str()).send().await?;
        let default_filter = response.json::<Vec<DefaultFilter>>().await?;
        Ok(default_filter)
    }

    pub fn get_enabled_filters(&self) -> Vec<&Filter> {
        self.filters
            .iter()
            .filter(|filter| filter.enabled)
            .collect()
    }

    pub async fn update_filters(&self, http_client: Client) -> ConfigurationResult<()> {
        debug!("Updating filters");

        let futures = self.filters.iter().filter_map(|filter| {
            if filter.enabled {
                Some(filter.update(&http_client))
            }
            None
        });

        try_join_all(futures).await?;

        Ok(())
    }


    // Getters in blow
    pub fn get_exclusion(&self) -> ConfigurationResult<Vec<String>> {
        Ok(self.exclusions.clone().into_iter().collect())
    }

    pub fn get_certificate(&self) -> ConfigurationResult<(X509, PKey<Private>)> {
        let x509 = match X509::from_pem(self.ca.ca_certificate.as_bytes()) {
            Ok(x509) => x509,
            Err(err) => {
                error!("Unable to decode ca certificate: {:?}", err);
                std::process::exit(1)
            }
        };
        let p_key = match PKey::private_key_from_pem(self.ca.ca_private_key.as_bytes()) {
            Ok(pem) => pem,
            Err(err) => {
                error!("Unable to decode ca private key: {:?}", err);
                std::process::exit(1)
            }
        };

        Ok((x509, p_key))
    }

}

fn get_home_directory() -> ConfigurationResult<PathBuf> {
    // dirs crate 사용해 home_dir 구함.
    match dirs::home_dir() {
        Some(dir) => Ok(dir),
        None => Err(ConfigurationError::HomeDirectoryNotFound),
    }
}

async fn get_filter(
    filter_file_name: &str,
    http_client: &Client,
) -> ConfigurationResult<String> {
    let base_filters_url = BASE_FILTERS_URL.parse::<Url>().unwrap();
    let filter_url = base_filters_url.join(filter_file_name).unwrap();

    let response = http_client.get(filter_url.as_str()).send().await?;

    let filter = response.text().await?;

    Ok(filter)
}

pub struct ConfigurationUpdater {
    filters_updater_abort_handle: AbortHandle,
    rx: Receiver<Configuration>,
    pub tx: Sender<Configuration>,
    http_client: reqwest::Client,
    adblock_requester: AdblockRequester,
}

impl ConfigurationUpdater {
    pub(crate) async fn new(
        configuration: Configuration,
        http_client: Client,
        adblock_requester: AdblockRequester,
        tx_rx: Option<(
            Sender<Configuration>,
            Receiver<Configuration>
        )>,
    ) -> Self {
        let (abort_handle, abort_registration) = AbortHandle::new_pair();

        let (tx, rx) = match tx_rx {
            Some((tx, rx)) => (tx, rx),
            None => channel(1),
        };

        let http_client_clone = http_client.clone();
        let adblock_requester_clone = adblock_requester.clone();

        let filters_updater = Abortable::new(
            async move {
                Self::filters_updater(
                    configuration,
                    adblock_requester_clone,
                    http_client_clone.clone(),
                ).await
            },
            abort_registration,
        );

        spawn(filters_updater);

        Self {
            filters_updater_abort_handle: abort_handle,
            rx,
            tx,
            http_client,
            adblock_requester: adblock_request,
        }

    }

    pub(crate) fn start(mut self) {
        spawn(async move {
            if let Some(configuration) = self.rx.recv().await {
                self.filters_updater_abort_handle.abort();

                let filters = get_filters_content(&configuration, &self.http_client).await;

                self.adblock_requester.replace_engine(filters).await;

                let new_self = Self::new(
                    configuration,
                    self.http_client,
                    self.adblock_requester,
                    Some((self.tx, self.rx)),
                ).await;

                new_self.start();

                info!("Applied new configuration");
            }
        });
    }


    async fn filters_updater(
        configuration: Configuration,
        adblock_requester: AdblockRequester,
        http_client: Client,
    ) {
        loop {
            sleep(FILTERS_UPDATE_AFTER).await;

            if let Err(err) = configuration.update_filters(http_client.clone()).await {
                error!("An error occurred while trying to update filters: {:?}", err);
            }

            let filters = get_filters_content(&configuration, &http_client).await;
            adblock_requester.replace_engine(filters).await;

            info!("Updated filters");
        }
    }
}

async fn get_filters_content(
    configuration: &Configuration,
    http_client: &Client,
) -> Vec<String> {
    let mut filters = Vec::new();

    for filter in configuration.get_enabled_filters() {
        match filter.get_contents(http_client).await {
            Ok(filter) => filters.push(filter),
            Err(err) => {
                error!("Unable to retrieve filter: {:?}, skipping.", err)
            }
        }
    }

    filters.append(&mut configuration.custom_filter.clone());

    filters
}

