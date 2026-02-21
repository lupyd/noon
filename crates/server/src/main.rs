use std::{convert::Infallible, net::SocketAddr, sync::Arc};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, Response, StatusCode, body::Incoming, header, service::service_fn};
use hyper_util::rt::TokioIo;

mod auth;
mod lupyd_token;
mod shared_data;
mod utils;

use crate::shared_data::SharedData;

#[tokio::main]
async fn main() {
    println!("Noon Server v{}", env!("CARGO_PKG_VERSION"));
    init_logger();
    let port = std::env::var("PORT")
        .map(|e| e.parse().unwrap_or(39210))
        .unwrap_or(39210);
    start_http_server(port).await.unwrap();
}

fn init_logger() {
    use tracing_subscriber::EnvFilter;
    tracing_subscriber::fmt::fmt()
        .with_file(true)
        .with_line_number(true)
        .with_env_filter(EnvFilter::from_default_env())
        .init();
}

async fn start_http_server(port: u16) -> Result<(), anyhow::Error> {
    let addr: SocketAddr = ([0, 0, 0, 0], port).into();

    let listener = tokio::net::TcpListener::bind(addr).await?;

    let sd = Arc::new(SharedData::new());

    while let Ok((stream, addr)) = listener.accept().await {
        let sd = sd.clone();

        tokio::spawn(async move {
            let service = service_fn(move |req: Request<Incoming>| service(req, sd.clone()));
            let executor = hyper_util::rt::TokioExecutor::new();
            if let Err(err) = hyper_util::server::conn::auto::Builder::new(executor)
                .serve_connection(TokioIo::new(stream), service)
                .await
            {
                log::error!("Error serving connection [{}]: {}", addr, err);
            }
        });
    }

    Ok(())
}

async fn limit_and_collect(
    body: Incoming,
    limit: usize,
) -> Result<Bytes, Box<dyn std::error::Error + Send + Sync>> {
    Ok(Limited::new(body, limit).collect().await?.to_bytes())
}
type Resp = Response<Full<Bytes>>;

const NOT_FOUND_STR: &str = "We couldn't find the resource, you are looking for";
const INTERNAL_SERVER_STR: &str = "This shouldn't have happened, Server is on fire 🔥🔥🔥 !!!";
const REQUEST_TIMEOUT_STR: &str = "You are taking too long  ";
const BAD_REQUEST_STR: &str = "You've missed something out";
const PAYLOAD_TOO_LARGE_STR: &str = "Your payload is huge";
const UNIMPLEMENTED_STR: &str = "Nah, We don't do that here";
const BAD_GATEWAY_STR: &str = "You sure this is where you are trying to come";
const UNAUTH_STR: &str = "You are missing some permissions";
const RATELIMIT_STR: &str = "You've hit the ratelimit, either login(if not already) to prevent ip ratelimiting or request an upgrade if you want to use lupyd services for any other purposes than regular browsing";

pub fn build_response(status: StatusCode, body: impl Into<Bytes>) -> Resp {
    response_builder()
        .status(status)
        .body(full_body(body))
        .unwrap()
}

#[inline(always)]
pub fn ok_response(body: impl Into<Bytes>) -> Resp {
    build_response(StatusCode::OK, body)
}

#[inline(always)]
pub fn server_timeout_response() -> Resp {
    build_response(StatusCode::REQUEST_TIMEOUT, REQUEST_TIMEOUT_STR)
}

#[inline(always)]
pub fn internal_error_response() -> Resp {
    build_response(StatusCode::INTERNAL_SERVER_ERROR, INTERNAL_SERVER_STR)
}

#[inline(always)]
pub fn not_found_response() -> Resp {
    build_response(StatusCode::NOT_FOUND, NOT_FOUND_STR)
}

#[inline(always)]
pub fn payload_too_large_response() -> Resp {
    build_response(StatusCode::PAYLOAD_TOO_LARGE, PAYLOAD_TOO_LARGE_STR)
}

#[inline(always)]
#[allow(unused)]
pub fn unimplemented_response() -> Resp {
    build_response(StatusCode::NOT_IMPLEMENTED, UNIMPLEMENTED_STR)
}

#[inline(always)]
pub fn bad_gateway_response() -> Resp {
    build_response(StatusCode::BAD_GATEWAY, BAD_GATEWAY_STR)
}

pub fn option_response() -> Resp {
    response_builder()
        .header(header::CACHE_CONTROL, "public, max-age=3600")
        .body(full_body(Bytes::new()))
        .unwrap()
}

#[inline(always)]
fn full_body(body: impl Into<Bytes>) -> Full<Bytes> {
    Full::new(body.into())
}

pub fn response_builder() -> hyper::http::response::Builder {
    let allow_origin = "*";

    Response::builder()
        .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, allow_origin)
        .header(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            "GET, POST, PUT, DELETE, OPTIONS, PATCH",
        )
        .header(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            "authorization, content-type",
        )
        .header(header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true")
}

#[inline(always)]
pub fn bad_request_response() -> Resp {
    build_response(StatusCode::BAD_REQUEST, BAD_REQUEST_STR)
}

#[inline(always)]
pub fn bad_request_with_reason(reason: impl Into<Bytes>) -> Resp {
    build_response(StatusCode::BAD_REQUEST, reason)
}

#[inline(always)]
pub fn unauthorized_response() -> Resp {
    build_response(StatusCode::UNAUTHORIZED, UNAUTH_STR)
}

#[inline(always)]
pub fn too_many_requests() -> Resp {
    build_response(StatusCode::TOO_MANY_REQUESTS, RATELIMIT_STR)
}

#[inline(always)]
pub fn empty_response() -> Resp {
    ok_response(Bytes::new())
}

async fn service(
    request: Request<Incoming>,
    sd: Arc<SharedData>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let uri = request.uri();

    let path = uri.path();

    match path {
        "/health" => {
            let response = ok_response("OK");
            Ok(response)
        }
        _ => {
            let response = not_found_response();
            Ok(response)
        }
    }
}
