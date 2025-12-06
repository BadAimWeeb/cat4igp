mod client;

use axum::{Router, extract::Request, http::{HeaderMap, StatusCode}, middleware::Next, response::Response, routing::{get, post}};

use crate::db;

pub async fn make_router() -> Result<Router, Box<dyn std::error::Error>> {
    Ok(
        Router::new()
            .route("/", axum::routing::get(|| async { "CAT4IGP Controller Server - https://github.com/BadAimWeeb/cat4igp" }))
            .nest("/client", make_router_client().await?)
            .nest("/operator", make_router_operator().await?)
    )
}

async fn auth_middleware(mut request: Request, next: Next) -> Response {
    let token_option: Option<&str> = if let Some(auth_header) = request.headers().get("Authorization") {
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

pub async fn make_router_client() -> Result<Router, Box<dyn std::error::Error>> {
    Ok(
        Router::new()
            .route("/update_name", post(client::update_name))
            .route("/self_info", get(client::get_self_info))
            .route("/all_nodes", get(client::get_all_nodes))
            // future: please add routes BEFORE this "layer" line.
            .layer(axum::middleware::from_fn(auth_middleware))
            .route("/register", post(client::register))
    )
}

pub async fn make_router_operator() -> Result<Router, Box<dyn std::error::Error>> {
    Ok(Router::new())
}
