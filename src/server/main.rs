use privaxy_lib::start_privaxy;

const PRIVAXY_STUDY_LOG_ENV_KEY: &str = "RUST_LOG";

#[tokio::main]
async fn main() {
    if std::env::var(PRIVAXY_STUDY_LOG_ENV_KEY).is_err() {
        std::env::set_var(PRIVAXY_STUDY_LOG_ENV_KEY, "debug");
    }
    env_logger::init();

    start_privaxy().await;

    // tokio::time::sleep(Duration::from_secs(60 * 60)).await;
}
