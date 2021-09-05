mod basic;
mod cookie_session;
mod form_login;
mod anonymous;
mod redirect;

pub use basic::BasicFilter;

use anyhow::Result;
use hyper::{client::HttpConnector, Client};
use hyper::{Body, Request, Response, StatusCode};

use crate::config::FilterConf;
use crate::filters::cookie_session::CookieSessionFilter;
use crate::filters::form_login::FormLoginFilter;
use crate::filters::anonymous::AnonymousFilter;
use crate::filters::redirect::RedirectFilter;

type DynFilter = dyn Filter + Send + Sync + 'static;

pub struct Next<'a> {
    client: hyper::Client<hyper::client::HttpConnector>,
    rest: &'a [Box<DynFilter>],
}

impl Next<'_> {
    pub async fn next(self, req: Request<Body>) -> Result<Response<Body>> {
        match self.rest.split_first() {
            Some((head, rest)) => {
                let next = Next {
                    client: self.client,
                    rest,
                };
                head.apply(req, next).await
            }
            None => Ok(Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::empty())?),
        }
    }

    pub async fn finish(self, req: Request<Body>) -> Result<Response<Body>> {
        crate::target::route(req, self.client).await
    }
}

#[async_trait::async_trait]
pub trait Filter {
    async fn apply(&self, req: Request<Body>, next: Next<'_>) -> Result<Response<Body>>;
}

pub struct FilterChain {
    client: Client<HttpConnector>,
    filters: Vec<Box<DynFilter>>,
}

impl FilterChain {
    pub fn new() -> FilterChain {
        FilterChain {
            client: Client::new(),
            filters: vec![],
        }
    }

    pub fn from_config(config: &[FilterConf]) -> Result<FilterChain> {
        let mut chain = FilterChain::new();
        for filter in config {
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
                FilterConf::Redirect(config) => {
                    chain.add(RedirectFilter::new(config)?)
                }
            }
        }

        Ok(chain)
    }

    pub fn add(&mut self, filter: impl Filter + Send + Sync + 'static) {
        self.filters.push(Box::new(filter));
    }

    pub async fn apply(&self, req: Request<Body>) -> Result<Response<Body>> {
        let next = Next {
            client: self.client.clone(),
            rest: self.filters.as_slice(),
        };
        next.next(req).await
    }
}
