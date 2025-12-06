pub mod models;
pub mod schema;
pub mod db;
pub mod ext;
pub mod router;

use dotenvy::dotenv;
use std::env;
use serde::{Deserialize, Serialize};

#[tokio::main]
async fn main() {
    dotenv().ok();

    // initialize tracing
    tracing_subscriber::fmt::init();

    // build our application with a route
    let app = router::make_router().await.unwrap();

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind(env::var("BIND_HOST_PORT").expect("BIND_HOST_PORT must be set")).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
