
use privaxy_lib::start_privaxy;

// env_logger 는 RUST_LOG 이름 으로 추적해 동작함.
const RUST_LOG_ENV_KEY: &str = "RUST_LOG";

#[tokio::main]
async fn main() {

    if std::env::var(RUST_LOG_ENV_KEY).is_err() {
        // logger level debug 로 설정. (debug, error console 에 표시됨)
        std::env::set_var(RUST_LOG_ENV_KEY, "privaxy=debug");
    }
    env_logger::init();

    start_privaxy().await;
    // tokio::time::sleep(Duration::from_secs(60 * 60)).await;
}
