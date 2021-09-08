use crate::config::TlsConfig;
use anyhow::{Context, Result};
use rustls::{Certificate, PrivateKey, ServerConfig};
use std::fs::File;
use std::io::BufReader;

fn load_certs(filename: &str) -> Result<Vec<Certificate>> {
    let certfile =
        File::open(filename).context(format!("error opening tls certificates: {}", filename))?;

    let mut reader = BufReader::new(certfile);
    Ok(rustls_pemfile::certs(&mut reader)
        .context("error loading tls certificates")?
        .iter()
        .map(|v| rustls::Certificate(v.clone()))
        .collect())
}

fn load_private_key(filename: &str) -> Result<PrivateKey> {
    let keyfile =
        File::open(filename).context(format!("error opening tls keyfile: {}", filename))?;

    let mut reader = BufReader::new(keyfile);

    loop {
        let item = rustls_pemfile::read_one(&mut reader).context("error parsing tls keyfile")?;

        match item {
            Some(rustls_pemfile::Item::RSAKey(key)) => return Ok(PrivateKey(key)),
            Some(rustls_pemfile::Item::PKCS8Key(key)) => return Ok(PrivateKey(key)),
            None => break,
            _ => {}
        }
    }

    anyhow::bail!(
        "no keys found in {:?} (encrypted keys not supported)",
        filename
    )
}

pub fn get_server_tls_config(tls_config: &TlsConfig) -> Result<ServerConfig> {
    let certs = load_certs(&tls_config.cert_file)?;
    let key = load_private_key(&tls_config.key_file)?;

    let mut server_config = ServerConfig::new(rustls::NoClientAuth::new());
    server_config.set_single_cert(certs, key)?;

    Ok(server_config)
}
