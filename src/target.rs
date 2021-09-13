use crate::config::Target;
use crate::session::Claims;
use anyhow::Result;
use hyper::{client::HttpConnector, Client};
use hyper::{Body, Request, Response};
use std::convert::TryInto;
use tracing::info;

pub fn add_header_claims(req: &mut Request<Body>, claims: Claims) -> Result<()> {
    let headers = req.headers_mut();
    headers.insert("X-Seal-Username", claims.subject.try_into()?);
    headers.insert("X-Seal-Mechanism", claims.issuer.try_into()?);

    Ok(())
}

#[tracing::instrument(skip(req, client, target))]
pub async fn route(
    req: Request<Body>,
    client: &Client<HttpConnector>,
    target: &Target,
) -> Result<Response<Body>> {
    let path = req.uri().path();
    assert!(path.starts_with("/"));

    let mut url = target.url.join(&path[1..])?;
    url.set_query(req.uri().path_and_query().and_then(|pnq| pnq.query()));

    info!(target=%url, "request");

    let (mut parts, body) = req.into_parts();
    parts.uri = url.as_str().parse()?;
    let proxy_req = Request::from_parts(parts, body);
    let resp = client.request(proxy_req).await?;

    info!(status=?resp.status(), "reply");
    return Ok(resp);

    /*warn!("no target matched");
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::BAD_GATEWAY;
    Ok(resp)*/
}
