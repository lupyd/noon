use std::str::FromStr;

use deadpool_postgres::{
    tokio_postgres::{self, config::SslMode, Config, NoTls},
    Manager,
};

use crate::email::Emailer;

pub struct SharedData {
    pub db: deadpool_postgres::Pool,
    pub emailer: Option<Emailer>,
    pub skip_email_sending: bool,
    pub auth_iss: String,
    pub auth_aud: String,
}

impl SharedData {
    pub fn new() -> Self {
        use std::env::var;

        let pool = build_pool();

        let skip_email_sending = var("SKIP_EMAIL_SENDING")
            .map(|s| s.to_lowercase() == "true")
            .unwrap_or(false);

        let emailer = if skip_email_sending {
            log::info!("SKIP_EMAIL_SENDING is set to true. Emailer will be disabled.");
            None
        } else {
            match Emailer::new() {
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

        let auth_iss = var("AUTH_ISS").unwrap_or_else(|_| "noon.lupyd.com".to_string());
        let auth_aud = var("AUTH_AUD").unwrap_or_else(|_| "noon-api".to_string());

        Self {
            db: pool,
            emailer,
            skip_email_sending,
            auth_iss,
            auth_aud,
        }
    }
}

fn build_pool() -> deadpool_postgres::Pool {
    let conn_str = std::env::var("DB_CONN_STR").expect("Missing DB_CONN_STR env var");

    let mut config = Config::from_str(&conn_str).unwrap();

    let manager_config = deadpool_postgres::ManagerConfig {
        recycling_method: deadpool_postgres::RecyclingMethod::Fast,
    };

    let manager = if config.get_ssl_mode() == SslMode::Disable {
        Manager::from_config(config, NoTls, manager_config)
    } else {
        let tls_config = postgres_tls_config(&std::env::var("DB_CERT").ok()).unwrap();
        let tls = tokio_postgres_rustls::MakeRustlsConnect::new(tls_config);

        config.ssl_mode(tokio_postgres::config::SslMode::Require);
        Manager::from_config(config, tls, manager_config)
    };

    let pool_size = std::env::var("DB_POOL_SIZE")
        .map(|s| s.parse::<usize>().unwrap_or(100))
        .unwrap_or(100);

    let pool = deadpool_postgres::Pool::builder(manager)
        .max_size(pool_size)
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
