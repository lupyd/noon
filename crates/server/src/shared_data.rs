use std::str::FromStr;

use deadpool_postgres::{
    tokio_postgres::{self, config::SslMode, NoTls},
    Manager,
};

use crate::email::Emailer;

use std::sync::Arc;
use tokio::sync::RwLock;
use noon_core::blind::BlindSigner;

pub struct AppConfig {
    pub db_conn_str: String,
    pub db_pool_size: usize,
    pub db_cert: Option<String>,
    pub skip_email_sending: bool,
    pub auth_iss: String,
    pub auth_aud: String,
    pub frontend_url: String,
    pub max_participants: usize,
    pub smtp_pool_size: usize,
}

pub struct KeyCache {
    pub blind_signer: RwLock<Option<Arc<BlindSigner>>>,
    pub jwt_secret: RwLock<Option<(Vec<u8>, SystemTime)>>,
    pub jwt_recent_secrets: RwLock<Option<Vec<Vec<u8>>>>,
}

pub struct SharedData {
    pub config: AppConfig,
    pub db: deadpool_postgres::Pool,
    pub emailer: Option<Emailer>,
    pub cache: KeyCache,
}

use std::time::SystemTime;

impl SharedData {
    pub fn new() -> Self {
        use std::env::var;

        let config = AppConfig {
            db_conn_str: var("DB_CONN_STR").expect("Missing DB_CONN_STR env var"),
            db_pool_size: var("DB_POOL_SIZE")
                .map(|s| s.parse::<usize>().unwrap_or(100))
                .unwrap_or(100),
            db_cert: var("DB_CERT").ok(),
            skip_email_sending: var("SKIP_EMAIL_SENDING")
                .map(|s| s.to_lowercase() == "true")
                .unwrap_or(false),
            auth_iss: var("AUTH_ISS").unwrap_or_else(|_| "noon.lupyd.com".to_string()),
            auth_aud: var("AUTH_AUD").unwrap_or_else(|_| "noon-api".to_string()),
            frontend_url: var("FRONTEND_URL").unwrap_or_else(|_| "http://localhost:8080".to_string()),
            max_participants: var("MAX_PARTICIPANTS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(10),
            smtp_pool_size: var("SMTP_POOL_SIZE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(4),
        };

        let pool = build_pool(&config);

        let emailer = if config.skip_email_sending {
            log::info!("SKIP_EMAIL_SENDING is set to true. Emailer will be disabled.");
            None
        } else {
            match Emailer::new(config.smtp_pool_size) {
                Ok(e) => {
                    log::info!("Emailer initialized successfully");
                    Some(e)
                }
                Err(e) => {
                    log::warn!(
                        "Failed to initialize emailer: {}. SMTP features will be disabled.",
                        e
                    );
                    None
                }
            }
        };

        Self {
            db: pool,
            emailer,
            config,
            cache: KeyCache {
                blind_signer: RwLock::new(None),
                jwt_secret: RwLock::new(None),
                jwt_recent_secrets: RwLock::new(None),
            },
        }
    }
}

fn build_pool(config: &AppConfig) -> deadpool_postgres::Pool {
    let mut pg_config = tokio_postgres::Config::from_str(&config.db_conn_str).unwrap();

    let manager_config = deadpool_postgres::ManagerConfig {
        recycling_method: deadpool_postgres::RecyclingMethod::Fast,
    };

    let manager = if pg_config.get_ssl_mode() == SslMode::Disable {
        Manager::from_config(pg_config, NoTls, manager_config)
    } else {
        let tls_config = postgres_tls_config(&config.db_cert).unwrap();
        let tls = tokio_postgres_rustls::MakeRustlsConnect::new(tls_config);

        pg_config.ssl_mode(tokio_postgres::config::SslMode::Require);
        Manager::from_config(pg_config, tls, manager_config)
    };

    let pool = deadpool_postgres::Pool::builder(manager)
        .max_size(config.db_pool_size)
        .build()
        .unwrap();

    pool
}

fn postgres_tls_config(cert_path: &Option<String>) -> anyhow::Result<rustls::ClientConfig> {
    let mut store = rustls::RootCertStore::empty();
    if let Some(cert_path) = cert_path {
        let f = std::fs::File::open(cert_path)?;
        let mut reader = std::io::BufReader::new(f);

        for cert in rustls_pemfile::certs(&mut reader) {
            store.add(cert?)?;
        }
        log::info!("Using {} certs from {cert_path}", store.roots.len());
    }

    Ok(rustls::ClientConfig::builder()
        .with_root_certificates(store)
        .with_no_client_auth())
}
