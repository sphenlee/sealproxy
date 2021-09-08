use crate::config::Config;
use crate::filters::FilterChain;
use anyhow::Result;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, StatusCode};
use std::convert::Infallible;
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;
use crate::tls::get_server_tls_config;
use hyper::server::conn::{AddrIncoming};
use futures_util::StreamExt;
use hyper::server::accept;
use arc_swap::ArcSwapOption;
use once_cell::sync::Lazy;

mod config;
mod filters;
pub mod session;
pub mod target;
pub mod userbase;
pub mod path_match;
mod tls;
mod logging;

struct State {
    config: Config,
    filters: FilterChain,
}

impl State {
    pub fn from_config(config: Config) -> Result<State> {
        let filters = FilterChain::from_config(&config)?;

        Ok(State {
            config,
            filters,
        })
    }
}


static STATE: Lazy<ArcSwapOption<State>> = Lazy::new(ArcSwapOption::empty);

#[tracing::instrument(
    skip(req),
    fields(
        url = % req.uri(),
        method = % req.method(),
        request_id = % Uuid::new_v4().to_string(),
    )
)]
async fn handle(req: Request<Body>) -> hyper::http::Result<Response<Body>> {
    let state = STATE.load_full().expect("state unset?");

    state.filters.apply(req).await.or_else(|err| {
        warn!(?err, "internal server error");
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(Body::empty())
    })
}

macro_rules! mk_service {
    ($state:expr) => {
        make_service_fn(move |_conn| {
            async move {
                Ok::<_, Infallible>(service_fn(move |req| {
                    handle(req)
                }))
            }
        })
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = dotenv::dotenv();

    logging::setup().expect("logging setup failed");

    let app = clap::App::new("sealproxy")
        .author("Steve Lee <sphen.lee@gmail.com>")
        .arg(clap::Arg::with_name("config")
            .long("--config")
            .short("-c")
            .takes_value(true)
            .required(true));

    let args = app.get_matches();

    let config_arg = args.value_of("config").expect("config is mandatory");
    let config = config::load(config_arg.as_ref())?;

    let state = Arc::new(State::from_config(config)?);
    STATE.store(Some(state.clone()));

    let bind = state.config.server.bind.as_deref().unwrap_or("0.0.0.0:8000");
    let addr = bind.parse()?;

    let incoming = AddrIncoming::bind(&addr)?;

    if let Some(tls_config) = &state.config.server.tls {
        let server_config = get_server_tls_config(tls_config)?;

        let tls = tls_listener::builder(server_config)
            .listen(incoming)
            .filter(|conn| {
                if let Err(err) = conn {
                    warn!("error accepting HTTPS connection: {}", err);
                    std::future::ready(false)
                } else {
                    std::future::ready(true)
                }
            });

        let mk_service = mk_service!(state);

        info!("server listening for HTTPS on {:?}", addr);
        hyper::Server::builder(accept::from_stream(tls)).serve(mk_service).await?;
    } else {
        let mk_service = mk_service!(state);

        info!("server listening for HTTP on {:?}", addr);
        hyper::Server::builder(incoming).serve(mk_service).await?;
    }

    Ok(())
}
