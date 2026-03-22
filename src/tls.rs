use crate::config::TlsConfig;
use anyhow::{Context, Result};
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

fn load_certs(filename: &str) -> Result<Vec<CertificateDer<'static>>> {
    let certfile =
        File::open(filename).context(format!("error opening tls certificates: {}", filename))?;

    let mut reader = BufReader::new(certfile);
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<_, _>>()
        .context("error loading tls certificates")?;

    Ok(certs)
}

fn load_private_key(filename: &str) -> Result<PrivateKeyDer<'static>> {
    let key = PrivateKeyDer::from_pem_file(filename)?;
    Ok(key)
}

pub fn get_server_tls_config(tls_config: &TlsConfig) -> Result<Arc<ServerConfig>> {
    let certs = load_certs(&tls_config.cert_file)?;
    let key = load_private_key(&tls_config.key_file)?;

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(Arc::new(server_config))
}
