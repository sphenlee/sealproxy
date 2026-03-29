use anyhow::Result;
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use hyper::upgrade::Upgraded;
use hyper::{Request, Response, Uri};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioIo;
use tracing::{info, trace, warn};

use crate::filters::empty_body;

pub async fn upgrade(
    req: Request<BoxBody<Bytes, hyper::Error>>,
    uri: Uri,
    client: &Client<HttpConnector, BoxBody<Bytes, hyper::Error>>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    // construct a request to forward to the target (copy method, uri, headers, but empty body)
    let mut proxy_req = Request::builder()
        .method(req.method())
        .uri(uri)
        .body(empty_body())?;
    *proxy_req.headers_mut() = req.headers().clone();

    // send the request to the target
    let resp = client.request(proxy_req).await?;

    // prepare the response to the client (copy the status and headers, but empty body)
    let mut switching = Response::builder()
        .status(resp.status())
        .body(empty_body())?;
    *switching.headers_mut() = resp.headers().clone();

    // let hyper upgrade the response from the target
    let client_upgraded = hyper::upgrade::on(resp).await?;

    // upgrade our response to the client - async; it won't resolve until we respond
    tokio::task::spawn(async {
        match do_handle_upgrade(req, client_upgraded).await {
            Ok(_) => trace!("upgraded connection ended"),
            Err(e) => warn!("error on upgraded connection: {:?}", e),
        }
    });

    // send response to client
    info!(status=?switching.status(), "reply");
    Ok(switching)
}

async fn do_handle_upgrade(
    req: Request<BoxBody<Bytes, hyper::Error>>,
    client_upgraded: Upgraded,
) -> anyhow::Result<()> {
    // let hyper upgrade our response to the client
    let server_upgraded = hyper::upgrade::on(req).await?;

    // wrap the upgraded connections so tokio can use them
    let mut client_io = TokioIo::new(client_upgraded);
    let mut server_io = TokioIo::new(server_upgraded);

    // forward messages in both directions between the upgraded connections
    tokio::io::copy_bidirectional(&mut client_io, &mut server_io).await?;
    Ok(())
}
