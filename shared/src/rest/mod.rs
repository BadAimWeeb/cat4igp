pub mod operator;
pub mod client;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct StandardResponse {
    pub success: bool,
    pub message: Option<String>,
}