use anyhow::Result;
use hyper::{Body, Request, Response, Uri, Client};
use hyper::upgrade::Upgraded;
use hyper::client::HttpConnector;
use tracing::{info, trace, warn};

pub async fn upgrade(req: Request<Body>, uri: Uri, client: &Client<HttpConnector>) -> Result<Response<Body>> {
    // construct a request to forward to the target (copy method, uri, headers, but empty body)
    let mut proxy_req = Request::builder()
        .method(req.method())
        .uri(uri)
        .body(Body::empty())?;
    *proxy_req.headers_mut() = req.headers().clone();

    // send the request to the target
    let resp = client.request(proxy_req).await?;

    // prepare the response to the client (copy the status and headers, but empty body)
    let mut switching = Response::builder()
        .status(resp.status())
        .body(Body::empty())?;
    *switching.headers_mut() = resp.headers().clone();

    // let hyper upgrade the response from the target
    let client_upgraded = hyper::upgrade::on(resp).await?;

    // upgrade our response to the client - async; it won't resolve until we respond
    tokio::task::spawn(async {
        match do_handle_upgrade(req, client_upgraded).await {
            Ok(_) =>  trace!("upgraded connection ended"),
            Err(e) => warn!("error on upgraded connection: {:?}", e),
        }
    });

    // send response to client
    info!(status=?switching.status(), "reply");
    Ok(switching)
}

async fn do_handle_upgrade(req: Request<Body>, mut client_upgraded: Upgraded) -> anyhow::Result<()> {
    // let hyper upgrade our response to the client
    let mut server_upgraded = hyper::upgrade::on(req).await?;
    // forward messages in both directions between the upgraded connections
    tokio::io::copy_bidirectional(&mut client_upgraded, &mut server_upgraded).await?;
    Ok(())
}
