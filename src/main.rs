use crate::config::CONFIG;
use crate::filters::FilterChain;
use anyhow::{anyhow, Result};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, StatusCode};
use std::convert::Infallible;
use std::sync::Arc;
use tracing::{info, warn};
use tracing_subscriber::prelude::*;
use uuid::Uuid;

mod config;
mod filters;
pub mod session;
pub mod target;
pub mod userbase;

struct State {
    filters: FilterChain,
}

impl State {
    #[tracing::instrument(
        skip(self, req),
        fields(
            url = % req.uri(),
            method = % req.method(),
            request_id = % Uuid::new_v4().to_string(),
        )
    )]
    async fn handle(self: Arc<Self>, req: Request<Body>) -> hyper::http::Result<Response<Body>> {
        self.filters.apply(req).await.or_else(|err| {
            warn!(?err, "internal server error");
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::empty())
        })
    }
}

fn enable_tracing() {
    let filter_layer = tracing_subscriber::EnvFilter::from_default_env();
    let format_layer = tracing_subscriber::fmt::layer();//.pretty();
    tracing_subscriber::registry()
        .with(filter_layer)
        .with(format_layer)
        .init();
}


#[tokio::main]
async fn main() -> Result<()> {
    enable_tracing();

    let app = clap::App::new("sealproxy")
        .author("Steve Lee <sphen.lee@gmail.com>")
        .arg(clap::Arg::with_name("config")
            .long("--config")
            .short("-c")
            .takes_value(true)
            .required(true));

    let args = app.get_matches();

    let config_arg = args.value_of("config").expect("config is mandatory");
    config::load(config_arg.as_ref())?;

    let config = CONFIG.load_full().unwrap();

    let state = Arc::new(State {
        filters: FilterChain::from_config(config.filters.as_slice())?,
    });

    let make_svc = make_service_fn(move |_conn| {
        let state = state.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let state = state.clone();
                state.handle(req)
            }))
        }
    });

    let bind = config.server.bind.as_deref().unwrap_or("0.0.0.0:8000");

    let addr = tokio::net::lookup_host(bind)
        .await?
        .next()
        .ok_or_else(|| anyhow!("host lookup returned no hosts"))?;

    let server = hyper::Server::try_bind(&addr)?.serve(make_svc);
    info!("server listening on {}", server.local_addr());
    server.await?;

    Ok(())
}
