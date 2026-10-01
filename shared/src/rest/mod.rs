pub mod operator;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct StandardResponse {
    pub success: bool,
    pub message: Option<String>,
}
