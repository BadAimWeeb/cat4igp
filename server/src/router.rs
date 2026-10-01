mod operator;

use axum::{
    Router, extract::Request, http::StatusCode, middleware::Next, response::Response, routing::post,
};

pub async fn make_router() -> Result<Router, Box<dyn std::error::Error>> {
    Ok(Router::new()
        .route(
            "/",
            axum::routing::get(|| async {
                "CAT4IGP Controller Server - https://github.com/BadAimWeeb/cat4igp"
            }),
        )
        .nest("/operator", make_router_operator().await?))
}

async fn auth_middleware_operator(request: Request, next: Next) -> Response {
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
        if operator_key.is_empty() {
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body("Unauthorized: Please set OPERATOR_AUTH_KEY environment variable".into())
                .unwrap()
        } else if token == operator_key {
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

pub async fn make_router_operator() -> Result<Router, Box<dyn std::error::Error>> {
    Ok(Router::new()
        .route("/create_invite", post(operator::create_invite))
        .layer(axum::middleware::from_fn(auth_middleware_operator)))
}
