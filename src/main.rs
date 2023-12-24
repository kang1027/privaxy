use std::time::Duration;

const PRIVAXY_STUDY_LOG_ENV_KEY: &str = "PRIVAXY_STUDY";

#[tokio::main]
async fn main() {
    if (std::env::var(PRIVAXY_STUDY_LOG_ENV_KEY).is_err()) {
        std::env::set_var(PRIVAXY_STUDY_LOG_ENV_KEY, "TEST");
    }
    env_logger::init();

    tokio::time::sleep(Duration::from_secs(60 * 60)).await;
}
