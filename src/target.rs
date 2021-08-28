use crate::config::CONFIG;
use anyhow::Result;
use hyper::{client::HttpConnector, Client};
use hyper::{Body, Request, Response};
use tracing::info;

#[tracing::instrument(skip(req, client))]
pub async fn route(req: Request<Body>, client: Client<HttpConnector>) -> Result<Response<Body>> {
    let config = CONFIG.load_full().unwrap();

    let path = req.uri().path();
    assert!(path.starts_with("/"));

    let url = config.target.url.join(&path[1..])?;
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