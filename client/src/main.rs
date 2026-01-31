mod config;
mod daemon;
mod interface;
mod network;
mod tunnel;

use daemon::protocol::DaemonRequest;
use daemon::client::DaemonClient;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "cat4igp-client")]
#[command(about = "cat4igp client daemon and CLI", long_about = None)]
struct Cli {
    /// Configuration file path
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the daemon
    Daemon {
        /// Configuration file path
        #[arg(short, long, value_name = "FILE")]
        config: Option<PathBuf>,
    },

    /// Configure server settings
    Server {
        /// Set server address and invite code (format: "address,invite_code")
        #[arg(long)]
        set: Option<String>,

        /// Get current server configuration
        #[arg(long)]
        get: bool,

        /// Register with server
        #[arg(long)]
        register: bool,
    },

    /// Daemon control commands
    Status,

    /// Generate a default configuration file
    GenConfig {
        /// Output file path
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,

        /// Generate as JSON instead of TOML
        #[arg(long)]
        json: bool,
    },

    /// Show configuration
    ShowConfig {
        /// Configuration file path
        #[arg(short, long, value_name = "FILE")]
        config: Option<PathBuf>,

        /// Output as JSON instead of TOML
        #[arg(long)]
        json: bool,
    },

    /// Detect public IP
    PublicIp {
        /// IP family (ipv4, ipv6, or both)
        family: Option<String>,

        /// Detect NAT type
        #[arg(long)]
        nat: bool,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let config_path = cli.config.clone().unwrap_or_else(|| {
        PathBuf::from("/etc/cat4igp/client.toml")
    });

    match cli.command {
        Some(Commands::Daemon { config: cmd_config }) => {
            let config_path = cmd_config.unwrap_or(config_path);
            let client_config = if config_path.exists() {
                config::ClientConfig::from_file(&config_path)?
            } else {
                println!("Configuration file not found: {:?}", config_path);
                config::ClientConfig::default()
            };

            start_daemon(client_config).await?;
        }

        Some(Commands::Server { set, get, register }) => {
            let client_config = if config_path.exists() {
                config::ClientConfig::from_file(&config_path)?
            } else {
                config::ClientConfig::default()
            };

            let client = DaemonClient::new(
                &client_config.daemon_socket,
                &client_config.data_dir,
            )?;

            if let Some(server_spec) = set {
                // Parse format: "address,invite_code"
                let parts: Vec<&str> = server_spec.split(',').collect();
                if parts.len() != 2 {
                    eprintln!("Error: --set requires format 'address,invite_code'");
                    std::process::exit(1);
                }

                let request = DaemonRequest::SetServer {
                    address: parts[0].to_string(),
                    invite_code: parts[1].to_string(),
                    verify_tls: true,
                };

                match client.send_request(request).await? {
                    daemon::protocol::DaemonResponse::Ok(msg) => {
                        println!("✓ {}", msg.unwrap_or("Server configured".to_string()));
                    }
                    daemon::protocol::DaemonResponse::Error(e) => {
                        eprintln!("✗ Error: {}", e);
                        std::process::exit(1);
                    }
                    _ => {
                        eprintln!("✗ Unexpected response");
                        std::process::exit(1);
                    }
                }
            } else if get {
                let request = DaemonRequest::GetServer;
                match client.send_request(request).await? {
                    daemon::protocol::DaemonResponse::ServerConfig {
                        address,
                        invite_code,
                        verify_tls,
                        registered,
                    } => {
                        println!("Server Configuration:");
                        println!("  Address: {}", address);
                        println!("  Invite Code: {}", invite_code);
                        println!("  Verify TLS: {}", verify_tls);
                        println!("  Registered: {}", if registered { "Yes" } else { "No" });
                    }
                    daemon::protocol::DaemonResponse::Error(e) => {
                        eprintln!("✗ Error: {}", e);
                        std::process::exit(1);
                    }
                    _ => {
                        eprintln!("✗ Unexpected response");
                        std::process::exit(1);
                    }
                }
            } else if register {
                let request = DaemonRequest::Register;
                match client.send_request(request).await? {
                    daemon::protocol::DaemonResponse::Ok(msg) => {
                        println!("✓ {}", msg.unwrap_or("Registered successfully".to_string()));
                    }
                    daemon::protocol::DaemonResponse::Error(e) => {
                        eprintln!("✗ Error: {}", e);
                        std::process::exit(1);
                    }
                    _ => {
                        eprintln!("✗ Unexpected response");
                        std::process::exit(1);
                    }
                }
            } else {
                eprintln!("Error: Specify --set, --get, or --register");
                std::process::exit(1);
            }
        }

        Some(Commands::Status) => {
            let client_config = if config_path.exists() {
                config::ClientConfig::from_file(&config_path)?
            } else {
                config::ClientConfig::default()
            };

            let client = DaemonClient::new(
                &client_config.daemon_socket,
                &client_config.data_dir,
            )?;

            let request = DaemonRequest::Status;
            match client.send_request(request).await? {
                daemon::protocol::DaemonResponse::Status {
                    running,
                    server_configured,
                    node_key_present,
                    message,
                } => {
                    println!("Daemon Status:");
                    println!("  Running: {}", if running { "Yes" } else { "No" });
                    println!("  Server Configured: {}", if server_configured { "Yes" } else { "No" });
                    println!("  Node Key Present: {}", if node_key_present { "Yes" } else { "No" });
                    if let Some(msg) = message {
                        println!("  Message: {}", msg);
                    }
                }
                daemon::protocol::DaemonResponse::Error(e) => {
                    eprintln!("✗ Error: {}", e);
                    std::process::exit(1);
                }
                _ => {
                    eprintln!("✗ Unexpected response");
                    std::process::exit(1);
                }
            }
        }

        Some(Commands::GenConfig { output, json }) => {
            let default_config = config::ClientConfig::default();
            if json {
                let content = default_config.to_json()?;
                std::fs::write(&output, content)?;
                println!("Generated JSON configuration to {:?}", output);
            } else {
                default_config.save_to_file(&output)?;
                println!("Generated TOML configuration to {:?}", output);
            }
        }

        Some(Commands::ShowConfig { config: cmd_config, json }) => {
            let config_path = cmd_config.unwrap_or(config_path);
            let client_config = if config_path.exists() {
                config::ClientConfig::from_file(&config_path)?
            } else {
                config::ClientConfig::default()
            };

            if json {
                println!("{}", client_config.to_json()?);
            } else {
                println!("{}", toml::to_string_pretty(&client_config)?);
            }
        }

        Some(Commands::PublicIp { family, nat }) => {
            let mut detector = network::public_ip::PublicIpDetector::new();
            
            // Initialize detector by fetching STUN server lists
            if let Err(e) = detector.init().await {
                eprintln!("Failed to initialize STUN detector: {}", e);
                std::process::exit(1);
            }
            
            if nat {
                // Detect NAT type
                match family.as_deref() {
                    Some("ipv4") | Some("IPv4") | Some("4") => {
                        match detector.detect_nat_type_ipv4().await {
                            Ok(nat_type) => println!("NAT Type (IPv4): {:?}", nat_type),
                            Err(e) => eprintln!("Error: {}", e),
                        }
                    }
                    Some("ipv6") | Some("IPv6") | Some("6") => {
                        match detector.detect_nat_type_ipv6().await {
                            Ok(nat_type) => println!("NAT Type (IPv6): {:?}", nat_type),
                            Err(e) => eprintln!("Error: {}", e),
                        }
                    }
                    None | Some("both") | Some("all") => {
                        match detector.detect_nat_type_ipv4().await {
                            Ok(nat_type) => println!("NAT Type (IPv4): {:?}", nat_type),
                            Err(e) => eprintln!("IPv4 NAT Error: {}", e),
                        }
                        match detector.detect_nat_type_ipv6().await {
                            Ok(nat_type) => println!("NAT Type (IPv6): {:?}", nat_type),
                            Err(e) => eprintln!("IPv6 NAT Error: {}", e),
                        }
                    }
                    Some(family) => {
                        eprintln!("Unknown family: {}. Use 'ipv4', 'ipv6', or 'both'", family);
                    }
                }
            } else {
                // Detect public IP
                match family.as_deref() {
                    Some("ipv4") | Some("IPv4") | Some("4") => {
                        match detector.detect_public_ipv4().await {
                            Ok(ip) => println!("Public IPv4: {}", ip),
                            Err(e) => eprintln!("Error: {}", e),
                        }
                    }
                    Some("ipv6") | Some("IPv6") | Some("6") => {
                        match detector.detect_public_ipv6().await {
                            Ok(ip) => println!("Public IPv6: {}", ip),
                            Err(e) => eprintln!("Error: {}", e),
                        }
                    }
                    None | Some("both") | Some("all") => {
                        match detector.detect_public_ipv4().await {
                            Ok(ip) => println!("Public IPv4: {}", ip),
                            Err(e) => eprintln!("IPv4 Error: {}", e),
                        }
                        match detector.detect_public_ipv6().await {
                            Ok(ip) => println!("Public IPv6: {}", ip),
                            Err(e) => eprintln!("IPv6 Error: {}", e),
                        }
                    }
                    Some(family) => {
                        eprintln!("Unknown family: {}. Use 'ipv4', 'ipv6', or 'both'", family);
                    }
                }
            }
        }

        None => {
            // Default to daemon mode
            let client_config = if config_path.exists() {
                config::ClientConfig::from_file(&config_path)?
            } else {
                config::ClientConfig::default()
            };

            start_daemon(client_config).await?;
        }
    }

    Ok(())
}

async fn start_daemon(config: config::ClientConfig) -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting cat4igp client daemon...");
    println!("Configuration:");
    println!("  Daemon socket: {:?}", config.daemon_socket);
    println!("  Data directory: {:?}", config.data_dir);
    println!("  Port range: {}-{}", config.port_range.min, config.port_range.max);

    if let Some(hostname) = &config.public_hostname_ipv4 {
        println!("  Public IPv4 hostname: {}", hostname);
    }
    if let Some(hostname) = &config.public_hostname_ipv6 {
        println!("  Public IPv6 hostname: {}", hostname);
    }

    let daemon = daemon::Daemon::new(config).await?;
    println!("✓ Daemon initialized");
    println!("  Daemon secret: {}", daemon.get_secret());

    if daemon.is_server_configured().await {
        println!("✓ Server is configured");
    } else {
        println!("⚠ Server not configured - waiting for CLI commands");
    }

    println!("Daemon is running...");

    // Run the daemon's Unix socket server
    daemon.run().await?;

    Ok(())
}

