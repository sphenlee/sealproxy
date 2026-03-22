use anyhow::Result;
use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::combinators::BoxBody;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use tls_listener::TlsListener;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};
use uuid::Uuid;

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
        let server_config = get_server_tls_config(tls_config)?;

        let acceptor = TlsAcceptor::from(server_config);

        info!("server listening for HTTPS on {:?}", addr);

        TlsListener::new(acceptor, incoming)
            .connections()
            .filter_map(|conn| {
                std::future::ready(match conn {
                    Err(err) => {
                        eprintln!("Error: {:?}", err);
                        None
                    }
                    Ok(c) => Some(TokioIo::new(c)),
                })
            })
            .for_each_concurrent(None, |conn| async {
                if let Err(err) = http1::Builder::new()
                    .serve_connection(conn, service_fn(handle))
                    .with_upgrades()
                    .await
                {
                    eprintln!("Error serving connection: {:?}", err);
                }
            })
            .await;
    } else {
        info!("server listening for HTTP on {:?}", addr);

        // We start a loop to continuously accept incoming connections
        loop {
            let (stream, _) = incoming.accept().await?;

            let io = TokioIo::new(stream);

            tokio::task::spawn(async move {
                if let Err(err) = http1::Builder::new()
                    .serve_connection(io, service_fn(handle))
                    .with_upgrades()
                    .await
                {
                    eprintln!("Error serving connection: {:?}", err);
                }
            });
        }
    }

    Ok(())
}
