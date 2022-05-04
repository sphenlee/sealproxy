use std::path::Path;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use arc_swap::ArcSwapOption;
use futures_util::stream::StreamExt;
use hyper::client::{Client, HttpConnector};
use hyper::{Body, Request, Response};
use inotify::{EventOwned, WatchMask};
use once_cell::sync::Lazy;
use tracing::{info, trace, warn};

use crate::config;
use crate::config::Config;
use crate::filters::{Context, FilterChain};
use jsonwebtoken::{EncodingKey, DecodingKey};

pub static STATE: Lazy<ArcSwapOption<State>> = Lazy::new(ArcSwapOption::empty);

pub struct State {
    pub config: Config,
    pub client: Client<HttpConnector>,
    pub session_key: EncodingKey,
    pub session_pub_key: DecodingKey<'static>,
    pub filters: FilterChain,
}

impl State {
    pub async fn from_config(config: Config) -> Result<State> {
        let filters = FilterChain::from_config(&config).await?;

        let pem = std::fs::read(&config.session.private_key_file)
            .context("error loading session private key")?;
        let session_key = EncodingKey::from_rsa_pem(pem.as_ref())?;

        let pem = std::fs::read(&config.session.public_key_file)
            .context("error reading session public key file")?;
        let session_pub_key = DecodingKey::from_rsa_pem(pem.as_ref())?.into_static();

        Ok(State {
            config,
            client: Client::new(),
            session_key,
            session_pub_key,
            filters,
        })
    }

    pub async fn handle(&self, req: Request<Body>) -> Result<Response<Body>> {
        let ctx = Context::new(&self);
        ctx.next(req).await
    }
}

pub async fn init(config_file: impl AsRef<Path>) -> Result<Arc<State>> {
    let config_file = config_file.as_ref().canonicalize()
        .context("config file path cannot be resolved")?;
    trace!(?config_file, "config file");

    start_file_watch(&config_file)?;
    reload_config(&config_file).await
}

fn start_file_watch(config_file: &Path) -> Result<()> {
    // TODO - fix these expects
    let os_config_file = config_file
        .file_name()
        .expect("config path has no filename?")
        .to_owned();

    let dir = config_file.parent().expect("config path has no parent?");
    trace!(?dir, "inotify watch directory");

    let mut watch = inotify::Inotify::init()?;
    watch
        .add_watch(&dir, WatchMask::CLOSE_WRITE | WatchMask::MOVED_TO)
        .context("error adding inotify watch on directory")?;

    tokio::task::spawn(async move {
        let mut buf = [0; 1024];
        let mut stream = watch.event_stream(&mut buf)?;

        while let Some(item) = stream.next().await {
            match item {
                Ok(EventOwned {
                    name: Some(name), ..
                }) if name == os_config_file => {
                    warn!("reloading configuration");
                    match reload_config(&os_config_file).await {
                        Ok(_) => info!("new config loaded successfully"),
                        Err(err) => warn!(
                            "new config is not valid, old config has been retained: {}",
                            err
                        ),
                    };
                }
                Ok(_) => {}
                Err(err) => warn!("inotify error: {:?}", err),
            }
        }

        panic!("inotify event stream ended!");

        // unreachable but needed for type inference of the async block
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    });

    Ok(())
}

async fn reload_config(file: impl AsRef<Path>) -> Result<Arc<State>> {
    let config = config::load(file.as_ref())?;

    let state = Arc::new(State::from_config(config).await?);
    STATE.store(Some(state.clone()));

    Ok(state)
}
