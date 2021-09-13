mod anonymous;
mod basic;
mod cookie_session;
mod form_login;
mod redirect;

pub use basic::BasicFilter;

use anyhow::Result;
use hyper::{client::HttpConnector, Client};
use hyper::{Body, Request, Response, StatusCode};

use crate::config::{Config, FilterConf};
use crate::filters::anonymous::AnonymousFilter;
use crate::filters::cookie_session::CookieSessionFilter;
use crate::filters::form_login::FormLoginFilter;
use crate::filters::redirect::RedirectFilter;

type DynFilter = dyn Filter + Send + Sync + 'static;

pub struct Context<'a> {
    config: &'a Config,
    client: Client<HttpConnector>,
    rest: &'a [Box<DynFilter>],
}

impl<'a> Context<'a> {
    pub fn new(config: &'a Config, filters: &'a FilterChain, client: Client<HttpConnector>) -> Self {
        Context {
            config,
            client,
            rest: filters.as_ref(),
        }
    }

    pub async fn next(self, req: Request<Body>) -> Result<Response<Body>> {
        match self.rest.split_first() {
            Some((head, rest)) => {
                let ctx = Context {
                    client: self.client,
                    config: self.config,
                    rest,
                };
                head.apply(req, ctx).await
            }
            None => Ok(Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::empty())?),
        }
    }

    pub async fn finish(self, req: Request<Body>) -> Result<Response<Body>> {
        crate::target::route(req, self.client, &self.config.target).await
    }
}

#[async_trait::async_trait]
pub trait Filter {
    async fn apply(&self, req: Request<Body>, ctx: Context<'_>) -> Result<Response<Body>>;
}

pub struct FilterChain {
    filters: Vec<Box<DynFilter>>,
}

impl FilterChain {
    pub fn from_config(config: &Config) -> Result<FilterChain> {
        let mut chain = FilterChain { filters: vec![] };

        for filter in &config.filters {
            match filter {
                FilterConf::Anonymous(config) => {
                    chain.add(AnonymousFilter::new(config)?);
                }
                FilterConf::Basic(config) => {
                    chain.add(BasicFilter::new(config)?);
                }
                FilterConf::CookieSession(config) => {
                    chain.add(CookieSessionFilter::new(config)?);
                }
                FilterConf::FormLogin(config) => {
                    chain.add(FormLoginFilter::new(config)?);
                }
                FilterConf::Redirect(config) => chain.add(RedirectFilter::new(config)?),
            }
        }

        Ok(chain)
    }

    pub fn add(&mut self, filter: impl Filter + Send + Sync + 'static) {
        self.filters.push(Box::new(filter));
    }
}

impl AsRef<[Box<DynFilter>]> for FilterChain {
    fn as_ref(&self) -> &[Box<DynFilter>] {
        self.filters.as_slice()
    }
}
