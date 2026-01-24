mod client;
mod operator;

use axum::{
    Router,
    extract::Request,
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
    routing::{get, post},
};

use crate::db;

pub async fn make_router() -> Result<Router, Box<dyn std::error::Error>> {
    Ok(Router::new()
        .route(
            "/",
            axum::routing::get(|| async {
                "CAT4IGP Controller Server - https://github.com/BadAimWeeb/cat4igp"
            }),
        )
        .nest("/client", make_router_client().await?)
        .nest("/operator", make_router_operator().await?))
}

async fn auth_middleware(mut request: Request, next: Next) -> Response {
    let token_option: Option<&str> =
        if let Some(auth_header) = request.headers().get("Authorization") {
            if let Ok(token_str) = auth_header.to_str() {
                Some(token_str)
            } else {
                None
            }
        } else {
            None
        };

    if let Some(token) = token_option {
        let conn = &mut db::establish_connection();
        let node_result = db::authenticate(conn, token);
        if let Ok(node) = node_result {
            request.extensions_mut().insert(node);
            next.run(request).await
        } else {
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body("Unauthorized".into())
                .unwrap()
        }
    } else {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body("Unauthorized".into())
            .unwrap()
    }
}

async fn auth_middleware_operator(mut request: Request, next: Next) -> Response {
    let token_option: Option<&str> =
        if let Some(auth_header) = request.headers().get("Authorization") {
            if let Ok(token_str) = auth_header.to_str() {
                Some(token_str)
            } else {
                None
            }
        } else {
            None
        };

    if let Some(token) = token_option {
        let operator_key = std::env::var("OPERATOR_AUTH_KEY").unwrap_or_default();
        if token == operator_key {
            next.run(request).await
        } else {
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body("Unauthorized".into())
                .unwrap()
        }
    } else {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body("Unauthorized".into())
            .unwrap()
    }
}

pub async fn make_router_client() -> Result<Router, Box<dyn std::error::Error>> {
    Ok(Router::new()
        .route("/self", post(client::update_name))
        .route("/self", get(client::get_self_info))
        .route("/all_nodes", get(client::get_all_nodes))
        .route("/wg_tun", get(client::get_wireguard_tunnels))
        .route("/wg_tun", post(client::answer_wireguard_tunnel))
        .route("/wg_pubkey", get(client::get_wireguard_pubkey))
        .route("/wg_pubkey", post(client::update_wireguard_pubkey))
        // future: please add routes BEFORE this "layer" line.
        .layer(axum::middleware::from_fn(auth_middleware))
        .route("/register", post(client::register)))
}

pub async fn make_router_operator() -> Result<Router, Box<dyn std::error::Error>> {
    Ok(Router::new()
        .route("/create_invite", post(operator::create_invite))
        .layer(axum::middleware::from_fn(auth_middleware_operator)))
}
