use reqwest::redirect::Policy;
pub mod configuration;
mod ca;

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

    configuration::Configuration::read_from_home(client.clone()).await.unwrap();
    // let config = match configuration::Configuration::read_from_home(client.clone()).await {
    //
    // }
}
