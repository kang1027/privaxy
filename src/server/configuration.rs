use crate::{ca::make_ca_certificate};
use std::collections::BTreeSet;
use std::io::Error;
use tokio::fs;
use std::path::{PathBuf};
use dirs::home_dir;
use log::{debug, info};
use reqwest::Url;
use thiserror::Error;
use serde::{Deserialize, Serialize};

type ConfigurationResult<T> = Result<T,ConfigurationError>;

const BASE_FILTERS_URL: &str = "https://filters.privaxy.net";
const METADATA_FILE_NAME: &str = "metadata.json";
const CONFIGURATION_DIRECTORY_NAME: &str = ".privaxy";
const CONFIGURATION_FILE_NAME: &str = "config";


#[derive(Deserialize)]
pub struct DefaultFilter {
    enabled_by_default: bool,
    file_name: String,
    group: String,
    title: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Filter {
    enabled: bool,
    file_name: String,
    group: FilterGroup,
    title: String,
}

#[derive(Debug, Serialize, Deserialize)]
enum FilterGroup {
    Default,
    Regional,
    Ads,
    Privacy,
    Malware,
    Social,
}

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

#[derive(Error, Debug)]
pub enum ConfigurationError {
    #[error("file system error")]
    FileSystemError(#[from] std::io::Error),
    #[error("this user home directory not found")]
    HomeDirectoryNotFound,
    #[error("unable store disconnected")]
    UnableToRetrieveDefaultFilters(#[from] reqwest::Error)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Ca {
    ca_certificate: String,
    ca_private_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Configuration {
    pub exclusions: BTreeSet<String>,
    pub custom_filter: Vec<String>,
    ca: Ca,
    pub filters: Vec<Filter>,
}

impl Configuration {
    pub async fn read_from_home(client: reqwest::Client) -> ConfigurationResult<Self>{
        let home_dir = get_home_directory()?;
        let configuration_directory = home_dir.join(CONFIGURATION_DIRECTORY_NAME);
        let configuration_file_path = configuration_directory.join(CONFIGURATION_FILE_NAME);

        // if privaxy directory not found, then creating directory.
        if let Err(err) = fs::metadata(&configuration_directory).await {
            let configuration = Self::create_dir_if_missing(&configuration_directory, client, err).await?;
            return Ok(configuration);
        }

        // if config file not found, then creating config file.
        return match fs::read(&configuration_file_path).await {
            Ok(bytes) => Ok(toml::from_str(&String::from_utf8_lossy(&bytes)).unwrap()),
            Err(err) => {
                if err.kind() == std::io::ErrorKind::NotFound {
                    debug!("Configuration file not found, creating one");

                    let configuration = Self::new_default(client).await?;
                    configuration.save_config_file().await?;
                    Ok(configuration)
                } else {
                    Err(ConfigurationError::FileSystemError(err))
                }
            }
        }

        // todo configuration_file_path 못읽을때 처리 필요.
    }

    async fn create_dir_if_missing(dir: &PathBuf, client: reqwest::Client, err: Error) -> ConfigurationResult<Self> {
        return if err.kind() == std::io::ErrorKind::NotFound {
            debug!("Configuration directory not found, creating one");
            match fs::create_dir(dir).await {
                Ok(_) => {
                    let configuration = Self::new_default(client).await?;
                    configuration.save_config_file().await?;
                    Ok(configuration)
                }
                Err(err) => {
                    Err(ConfigurationError::FileSystemError(err))
                }
            }
        } else {
            Err(ConfigurationError::FileSystemError(err))
        }
    }

    async fn new_default(client: reqwest::Client) -> ConfigurationResult<Self>{
        let default_filters = Self::get_default_filters(client).await?;

        let (x509, private_key) = make_ca_certificate();

        let x509_pem = std::str::from_utf8(&x509.to_pem().unwrap())
            .unwrap()
            .to_string();

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

    async fn save_config_file(&self) -> ConfigurationResult<()> {
        let home_directory = get_home_directory()?;
        let configuration_file_path = home_directory.join(CONFIGURATION_DIRECTORY_NAME).join(CONFIGURATION_FILE_NAME);

        let configuration_serialized = toml::to_string_pretty(&self).unwrap();
        fs::write(configuration_file_path, configuration_serialized).await?;

        Ok(())
    }

    async fn get_default_filters(client: reqwest::Client) -> ConfigurationResult<Vec<DefaultFilter>> {
        let url = BASE_FILTERS_URL.parse::<Url>().unwrap();
        let filters_url = url.join(METADATA_FILE_NAME).unwrap();
        let response = client.get(filters_url.as_str()).send().await?;
        let default_filter = response.json::<Vec<DefaultFilter>>().await?;
        Ok(default_filter)
    }
}


fn get_home_directory() -> ConfigurationResult<PathBuf> {
    match home_dir() {
        Some(dir) => Ok(dir),
        None => Err(ConfigurationError::HomeDirectoryNotFound),
    }
}