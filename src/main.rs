use anyhow::{anyhow, Result};
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use hyper_util::server::graceful::GracefulShutdown;
use rustls::crypto::aws_lc_rs;
use std::net::SocketAddr;
use tls_listener::TlsListener;
use tokio::net::TcpListener;
use tokio::signal::unix::{signal, SignalKind};
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};
use uuid::Uuid;

use crate::config::TlsConfig;
use crate::filters::empty_body;
use crate::state::STATE;
use crate::tls::get_server_tls_config;

mod config;
pub mod filters;
mod logging;
pub mod path_match;
pub mod session;
mod state;
pub mod target;
mod tls;
mod upgrade;
pub mod userbase;

#[tracing::instrument(
    skip(req),
    fields(
        url = % req.uri(),
        method = % req.method(),
        request_id = % Uuid::new_v4().to_string(),
    )
)]
async fn handle(req: Request<Incoming>) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    let state = STATE.load_full().expect("state unset?");

    state.handle(req).await.or_else(|err| {
        warn!(?err, "internal server error");
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(empty_body())
            .map_err(Into::into)
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenv::dotenv();

    logging::setup().expect("logging setup failed");

    aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow!("failed to install crypto provider"))?;

    let app = clap::Command::new("sealproxy")
        .author("Steve Lee <sphen.lee@gmail.com>")
        .arg(
            clap::Arg::new("config")
                .long("config")
                .short('c')
                .default_value("/etc/sealproxy/sealproxy.yml"),
        );

    let args = app.get_matches();

    let config_arg = args
        .get_one::<String>("config")
        .expect("config is mandatory")
        .as_str();
    let state = state::init(config_arg)?;

    let bind = state
        .config
        .server
        .bind
        .as_deref()
        .unwrap_or("0.0.0.0:8000");
    let addr: SocketAddr = bind.parse()?;

    let incoming = TcpListener::bind(addr).await?;

    if let Some(tls_config) = &state.config.server.tls {
        info!("server listening for HTTPS on {:?}", addr);
        serve_https(incoming, tls_config).await?;
    } else {
        info!("server listening for HTTP on {:?}", addr);
        serve_http(incoming).await?;
    }

    Ok(())
}

async fn serve_https(incoming: TcpListener, tls_config: &TlsConfig) -> anyhow::Result<()> {
    let server_config = get_server_tls_config(tls_config)?;
    let acceptor = TlsAcceptor::from(server_config);
    let server = auto::Builder::new(TokioExecutor::new());

    let mut sigterm = signal(SignalKind::terminate())?;
    let graceful = GracefulShutdown::new();

    let mut listener = TlsListener::new(acceptor, incoming);

    loop {
        tokio::select! {
            conn = listener.accept() => {
                let stream = match conn {
                    Ok((stream, _addr)) => TokioIo::new(stream),
                    Err(e) => {
                        warn!("accept error: {}", e);
                        continue;
                    }
                };


                let conn = server.serve_connection_with_upgrades(stream, service_fn(handle));
                let conn = graceful.watch(conn.into_owned());

                tokio::spawn(async move {
                    if let Err(err) = conn.await {
                        warn!("connection error: {}", err);
                    }
                });
            },

            _ = sigterm.recv() => {
                info!("Received SIGTERM, shutting down gracefully");
                drop(listener);
                break;
            }
        }
    }

    graceful.shutdown().await;
    Ok(())
}

async fn serve_http(incoming: TcpListener) -> anyhow::Result<()> {
    let server = auto::Builder::new(TokioExecutor::new());

    let mut sigterm = signal(SignalKind::terminate())?;
    let graceful = GracefulShutdown::new();

    loop {
        tokio::select! {
            conn = incoming.accept() => {
                let stream = match conn {
                    Ok((stream, _addr)) => TokioIo::new(stream),
                    Err(e) => {
                        warn!("accept error: {}", e);
                        continue;
                    }
                };


                let conn = server.serve_connection_with_upgrades(stream, service_fn(handle));
                let conn = graceful.watch(conn.into_owned());

                tokio::spawn(async move {
                    if let Err(err) = conn.await {
                        warn!("connection error: {}", err);
                    }
                });
            },

            _ = sigterm.recv() => {
                info!("Received SIGTERM, shutting down gracefully");
                drop(incoming);
                break;
            }
        }
    }

    graceful.shutdown().await;
    Ok(())
}
