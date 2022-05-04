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
use crate::session::Claims;
use crate::state::State;

type DynFilter = dyn Filter + Send + Sync + 'static;

pub struct Context<'a> {
    client: Client<HttpConnector>,
    state: &'a State,
    rest: &'a [Box<DynFilter>],
}

impl<'a> Context<'a> {
    pub fn new(state: &'a State) -> Self {
        Context {
            state,
            client: state.client.clone(),
            rest: state.filters.as_ref(),
        }
    }

    pub async fn next(self, req: Request<Body>) -> Result<Response<Body>> {
        match self.rest.split_first() {
            Some((head, rest)) => {
                let ctx = Context {
                    state: self.state,
                    client: self.client,
                    rest,
                };
                head.apply(req, ctx).await
            }
            None => Ok(Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::empty())?),
        }
    }

    pub async fn finish(&self, req: Request<Body>) -> Result<Response<Body>> {
        crate::target::route(req, &self.client, &self.state.config.target).await
    }

    pub fn establish_session(
        &self,
        resp: Response<Body>,
        claims: Claims,
    ) -> Result<Response<Body>> {
        crate::session::establish_session(resp, claims, &self.state)
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
    pub async fn from_config(config: &Config) -> Result<FilterChain> {
        let mut chain = FilterChain { filters: vec![] };

        for filter in &config.filters {
            match filter {
                FilterConf::Anonymous(config) => {
                    chain.add(AnonymousFilter::new(config)?);
                }
                FilterConf::Basic(config) => {
                    chain.add(BasicFilter::new(config).await?);
                }
                FilterConf::CookieSession(config) => {
                    chain.add(CookieSessionFilter::new(config)?);
                }
                FilterConf::FormLogin(config) => {
                    chain.add(FormLoginFilter::new(config).await?);
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
