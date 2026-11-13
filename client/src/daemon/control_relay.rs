use std::{io, net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinSet,
    time::{timeout, timeout_at, Instant},
};

const MAX_CONNECTIONS: usize = 128;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Relays opaque TCP streams to one fixed address. Dropping this future aborts its connections.
pub(super) async fn run(listener: TcpListener, target: SocketAddr) -> io::Result<()> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            result = listener.accept(), if connections.len() < MAX_CONNECTIONS => {
                let (client, _) = result?;
                connections.spawn(async move {
                    if let Ok(Ok(server)) = timeout(CONNECT_TIMEOUT, TcpStream::connect(target)).await {
                        let _ = relay(client, server, IDLE_TIMEOUT).await;
                    }
                });
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}

async fn relay(client: TcpStream, server: TcpStream, idle: Duration) -> io::Result<()> {
    let (mut client_read, mut client_write) = client.into_split();
    let (mut server_read, mut server_write) = server.into_split();
    let mut client_open = true;
    let mut server_open = true;
    let mut client_buffer = [0; 8192];
    let mut server_buffer = [0; 8192];
    let mut deadline = Instant::now() + idle;
    while client_open || server_open {
        tokio::select! {
            result = client_read.read(&mut client_buffer), if client_open => {
                let count = result?;
                if count == 0 {
                    client_open = false;
                    timeout_at(deadline, server_write.shutdown()).await??;
                } else {
                    timeout_at(deadline, server_write.write_all(&client_buffer[..count])).await??;
                    deadline = Instant::now() + idle;
                }
            }
            result = server_read.read(&mut server_buffer), if server_open => {
                let count = result?;
                if count == 0 {
                    server_open = false;
                    timeout_at(deadline, client_write.shutdown()).await??;
                } else {
                    timeout_at(deadline, client_write.write_all(&server_buffer[..count])).await??;
                    deadline = Instant::now() + idle;
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "relay idle timeout"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn relays_binary_data_and_half_closes() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let relay = tokio::spawn(run(listener, target.local_addr().unwrap()));
        let mut client = TcpStream::connect(address).await.unwrap();
        let (mut server, _) = target.accept().await.unwrap();
        client.write_all(&[0, 255, 1]).await.unwrap();
        client.shutdown().await.unwrap();
        let mut bytes = Vec::new();
        server.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, [0, 255, 1]);
        server.write_all(&[2, 0, 254]).await.unwrap();
        server.shutdown().await.unwrap();
        bytes.clear();
        client.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, [2, 0, 254]);
        relay.abort();
    }

    #[tokio::test]
    async fn idle_connection_closes_and_shutdown_aborts_children() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(run(listener, target.local_addr().unwrap()));
        let mut client = TcpStream::connect(address).await.unwrap();
        let (mut server, _) = target.accept().await.unwrap();
        task.abort();
        let _ = task.await;
        let mut byte = [0];
        assert_eq!(timeout(Duration::from_secs(2), client.read(&mut byte)).await.unwrap().unwrap(), 0);
        assert_eq!(timeout(Duration::from_secs(2), server.read(&mut byte)).await.unwrap().unwrap(), 0);

        let a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let b = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ac = TcpStream::connect(a.local_addr().unwrap()).await.unwrap();
        let (asock, _) = a.accept().await.unwrap();
        let bc = TcpStream::connect(b.local_addr().unwrap()).await.unwrap();
        let (bsock, _) = b.accept().await.unwrap();
        let error = relay(asock, bsock, Duration::from_millis(10)).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        drop((ac, bc));
    }
}
