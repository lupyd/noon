use noon_server::start_http_server;

#[tokio::main]
async fn main() {
    println!("Noon Server v{}", env!("CARGO_PKG_VERSION"));
    rustls::crypto::ring::default_provider().install_default().expect("Failed to install rustls crypto provider");

    if let Err(err) = dotenv::dotenv() {
        eprintln!("failed to load dotenv {}", err);
    }

    init_logger();
    let port = std::env::var("PORT")
        .map(|e| e.parse().unwrap_or(39210))
        .unwrap_or(39210);

    log::info!("log initialized");
    start_http_server(port).await.unwrap();
}

fn init_logger() {
    use tracing_subscriber::EnvFilter;
    tracing_subscriber::fmt::fmt()
        .with_file(true)
        .with_line_number(true)
        .with_env_filter(EnvFilter::from_default_env())
        .init();
}
