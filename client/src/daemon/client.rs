use std::path::Path;
use std::io;
use tokio::net::UnixStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::protocol::{DaemonRequest, DaemonResponse, SharedSecret};

/// IPC message envelope
#[derive(serde::Serialize, serde::Deserialize)]
struct IpcMessage {
    secret: String,
    request: DaemonRequest,
}

/// Client for communicating with the daemon via Unix socket
pub struct DaemonClient {
    socket_path: std::path::PathBuf,
    secret: String,
}

impl DaemonClient {
    /// Create a new daemon client
    pub fn new(socket_path: &Path, data_dir: &Path) -> io::Result<Self> {
        let secret = SharedSecret::load(data_dir)?;
        Ok(DaemonClient {
            socket_path: socket_path.to_path_buf(),
            secret: secret.value().to_string(),
        })
    }

    /// Send a request to the daemon and wait for response
    pub async fn send_request(&self, request: DaemonRequest) -> io::Result<DaemonResponse> {
        // Connect to the daemon socket
        let mut stream = UnixStream::connect(&self.socket_path).await.map_err(|e| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("Failed to connect to daemon at {:?}: {}", self.socket_path, e),
            )
        })?;

        // Prepare the message
        let message = IpcMessage {
            secret: self.secret.clone(),
            request,
        };

        let message_bytes = serde_json::to_vec(&message).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("Failed to serialize request: {}", e))
        })?;

        // Send length prefix
        let len = (message_bytes.len() as u32).to_be_bytes();
        stream.write_all(&len).await?;
        stream.write_all(&message_bytes).await?;
        stream.flush().await?;

        // Read response length
        let mut len_bytes = [0u8; 4];
        stream.read_exact(&mut len_bytes).await?;
        let response_len = u32::from_be_bytes(len_bytes) as usize;

        if response_len > 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Response too large",
            ));
        }

        // Read response
        let mut response_buffer = vec![0u8; response_len];
        stream.read_exact(&mut response_buffer).await?;

        let response: DaemonResponse = serde_json::from_slice(&response_buffer).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("Invalid response JSON: {}", e))
        })?;

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipc_message_serialization() {
        let message = IpcMessage {
            secret: "test-secret".to_string(),
            request: DaemonRequest::Status,
        };

        let serialized = serde_json::to_string(&message).unwrap();
        let deserialized: IpcMessage = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.secret, "test-secret");
    }
}
