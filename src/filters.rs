mod anonymous;
mod basic;
mod cookie_session;
mod form_login;
mod oauth2;
mod redirect;

pub use basic::BasicFilter;

use anyhow::Result;
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::{connect::HttpConnector, Client};

use crate::config::{Config, FilterConf};
use crate::filters::anonymous::AnonymousFilter;
use crate::filters::cookie_session::CookieSessionFilter;
use crate::filters::form_login::FormLoginFilter;
use crate::filters::oauth2::Oauth2Filter;
use crate::filters::redirect::RedirectFilter;
use crate::session::Claims;
use crate::state::State;

type DynFilter = dyn Filter + Send + Sync + 'static;

pub struct Context<'a> {
    client: Client<HttpConnector, BoxBody<Bytes, hyper::Error>>,
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

    pub async fn next(
        self,
        req: Request<Incoming>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
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
                .body(empty_body())?),
        }
    }

    pub async fn finish(
        &self,
        req: Request<Incoming>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
        let req = req.map(BodyExt::boxed);
        crate::target::route(req, &self.client, &self.state.config.target).await
    }

    pub fn establish_session(
        &self,
        resp: Response<BoxBody<Bytes, hyper::Error>>,
        claims: Claims,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
        crate::session::establish_session(resp, claims, self.state)
    }
}

pub fn empty_body() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

#[async_trait::async_trait]
pub trait Filter {
    async fn apply(
        &self,
        req: Request<Incoming>,
        ctx: Context<'_>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>>;
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
                FilterConf::Oauth2(config) => {
                    chain.add(Oauth2Filter::new(config)?);
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
