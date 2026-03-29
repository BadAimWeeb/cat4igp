use std::error::Error;

use cat4igp_shared::rest::client as rest;
use cat4igp_shared::rest::StandardResponse;
use reqwest::Method;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::config::ServerConfig;

#[derive(Clone)]
pub struct ServerRestClient {
    base_url: String,
    auth_key: Option<String>,
    client: reqwest::Client,
}

impl ServerRestClient {
    pub fn new(config: &ServerConfig) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(!config.verify_tls)
            .build()?;

        Ok(Self {
            base_url: config.address.trim_end_matches('/').to_string(),
            auth_key: config.node_key.clone(),
            client,
        })
    }

    fn request(&self, method: Method, path: &str) -> reqwest::RequestBuilder {
        let mut request = self
            .client
            .request(method, format!("{}/client/{}", self.base_url, path));

        if let Some(auth_key) = &self.auth_key {
            if !auth_key.is_empty() {
                request = request.header("Authorization", auth_key);
            }
        }

        request
    }

    async fn send_json<T, P>(
        &self,
        method: Method,
        path: &str,
        payload: Option<&P>,
    ) -> Result<T, Box<dyn Error + Send + Sync>>
    where
        T: DeserializeOwned,
        P: Serialize,
    {
        let request = self.request(method, path);
        let request = if let Some(payload) = payload {
            request.json(payload)
        } else {
            request
        };

        let response = request.send().await?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!("request failed with {}: {}", status, body).into());
        }

        Ok(response.json::<T>().await?)
    }

    pub async fn register(
        &self,
        node_name: &str,
        invite_code: &str,
    ) -> Result<rest::RegisterResponse, Box<dyn Error + Send + Sync>> {
        let payload = rest::RegisterPayload {
            node_name: node_name.to_string(),
            invitation_key: invite_code.to_string(),
        };

        self.send_json(Method::POST, "register", Some(&payload)).await
    }

    pub async fn get_self_info(&self) -> Result<rest::NodeInfoResponse, Box<dyn Error + Send + Sync>> {
        self.send_json::<rest::NodeInfoResponse, serde_json::Value>(Method::GET, "self", None)
            .await
    }

    pub async fn update_name(&self, new_name: &str) -> Result<StandardResponse, Box<dyn Error + Send + Sync>> {
        let payload = rest::UpdateNamePayload {
            new_name: new_name.to_string(),
        };
        self.send_json(Method::POST, "self", Some(&payload)).await
    }

    pub async fn get_all_nodes(&self) -> Result<rest::AllNodesResponse, Box<dyn Error + Send + Sync>> {
        self.send_json::<rest::AllNodesResponse, serde_json::Value>(
            Method::GET,
            "all_nodes",
            None,
        )
        .await
    }

    pub async fn get_wireguard_tunnels(
        &self,
    ) -> Result<rest::WireguardTunnelsResponse, Box<dyn Error + Send + Sync>> {
        self.send_json::<rest::WireguardTunnelsResponse, serde_json::Value>(
            Method::GET,
            "wg_tun",
            None,
        )
        .await
    }

    pub async fn answer_wireguard_tunnel(
        &self,
        payload: &rest::WireguardTunnelAnswerPayload,
    ) -> Result<StandardResponse, Box<dyn Error + Send + Sync>> {
        self.send_json(Method::POST, "wg_tun", Some(payload)).await
    }

    pub async fn get_wireguard_pubkey(
        &self,
        node_id_peer: i32,
    ) -> Result<rest::WireguardPubKeyResponse, Box<dyn Error + Send + Sync>> {
        let payload = rest::WireguardPubKeyAskPayload { node_id_peer };
        self.send_json(Method::GET, "wg_pubkey", Some(&payload)).await
    }

    pub async fn update_wireguard_pubkey(
        &self,
        public_key: &str,
    ) -> Result<StandardResponse, Box<dyn Error + Send + Sync>> {
        let payload = rest::WireguardPubKeyUpdatePayload {
            public_key: public_key.to_string(),
        };
        self.send_json(Method::POST, "wg_pubkey", Some(&payload)).await
    }
}
