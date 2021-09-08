mod basic;
mod cookie_session;
mod form_login;
mod anonymous;
mod redirect;

pub use basic::BasicFilter;

use anyhow::Result;
use hyper::{client::HttpConnector, Client};
use hyper::{Body, Request, Response, StatusCode};

use crate::config::{FilterConf, Config};
use crate::filters::cookie_session::CookieSessionFilter;
use crate::filters::form_login::FormLoginFilter;
use crate::filters::anonymous::AnonymousFilter;
use crate::filters::redirect::RedirectFilter;
use url::Url;

type DynFilter = dyn Filter + Send + Sync + 'static;

pub struct Next<'a> {
    client: hyper::Client<hyper::client::HttpConnector>,
    target: Url,
    rest: &'a [Box<DynFilter>],
}

impl Next<'_> {
    pub async fn next(self, req: Request<Body>) -> Result<Response<Body>> {
        match self.rest.split_first() {
            Some((head, rest)) => {
                let next = Next {
                    client: self.client,
                    target: self.target,
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
        crate::target::route(req, self.client, self.target).await
    }
}

#[async_trait::async_trait]
pub trait Filter {
    async fn apply(&self, req: Request<Body>, next: Next<'_>) -> Result<Response<Body>>;
}

pub struct FilterChain {
    client: Client<HttpConnector>,
    target: Url,
    filters: Vec<Box<DynFilter>>,
}

impl FilterChain {
    pub fn from_config(config: &Config) -> Result<FilterChain> {
        let mut chain = FilterChain {
            client: Client::new(),
            target: config.target.url.clone(),
            filters: vec![],
        };

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
            target: self.target.clone(),
            rest: self.filters.as_slice(),
        };
        next.next(req).await
    }
}
