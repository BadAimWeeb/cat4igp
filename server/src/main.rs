mod cluster;

#[cfg(test)]
extern crate rand08 as rand;

// Compile the shipped client paths unchanged for the real listener/Raft wire check.
#[cfg(test)]
#[path = "../../client/src/config/server.rs"]
mod client_config;
#[cfg(test)]
#[path = "../../client/src/daemon/control.rs"]
pub(crate) mod client_control;
#[cfg(test)]
mod config {
    pub use crate::client_config::ServerConfig;
}
#[cfg(test)]
mod daemon {
    pub(crate) use crate::client_control as control;
}
pub mod db;
pub mod ext;
pub mod models;
pub mod raft_network;
pub mod raft_storage;
pub mod router;
pub mod schema;

use diesel::Connection;
use dotenvy::dotenv;
use futures_util::StreamExt;
use libp2p::{
    StreamProtocol,
    core::{Transport, upgrade::Version},
    gossipsub, identity, noise,
    pnet::{PnetConfig, PreSharedKey},
    request_response::{self, json},
    swarm::{Config as SwarmConfig, NetworkBehaviour, Swarm},
    tcp, yamux,
};
use std::env;

const CONTROL_PROTOCOL: &str = "/cat4igp/control/1";

const DATABASE_QUEUE_CAPACITY: usize = 32;
pub(crate) type DatabaseSender = tokio::sync::mpsc::Sender<DatabaseJob>;
pub(crate) enum DatabaseJob {
    Control(
        libp2p::PeerId,
        cat4igp_shared::control::ControlRequest,
        request_response::ResponseChannel<cat4igp_shared::control::ControlResponse>,
    ),
    Invite {
        request_id: String,
        expires_at: Option<chrono::NaiveDateTime>,
        max_uses: Option<i32>,
        join_mesh: Option<i32>,
        reply: tokio::sync::oneshot::Sender<Result<Result<String, String>, diesel::result::Error>>,
    },
}

type ControlCompletion = (
    libp2p::PeerId,
    request_response::ResponseChannel<cat4igp_shared::control::ControlResponse>,
    cat4igp_shared::control::ControlResponse,
    Vec<(i32, Vec<u8>)>,
);

#[derive(NetworkBehaviour)]
struct ControlBehaviour {
    request_response: json::Behaviour<
        cat4igp_shared::control::ControlRequest,
        cat4igp_shared::control::ControlResponse,
    >,
    gossipsub: gossipsub::Behaviour,
}

fn gossipsub(keypair: &identity::Keypair) -> Result<gossipsub::Behaviour, String> {
    gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(keypair.clone()),
        gossipsub::ConfigBuilder::default()
            .protocol_id_prefix("/cat4igp/topology/1")
            .max_transmit_size(64 * 1024)
            .build()
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())
}

fn control_response(
    conn: &mut diesel::SqliteConnection,
    peer_id: &libp2p::PeerId,
    controller_signing_key: &str,
    controller_keypair: &identity::Keypair,
    network_id: &str,
    request: cat4igp_shared::control::ControlRequest,
) -> (
    cat4igp_shared::control::ControlResponse,
    Vec<cat4igp_shared::control::TopologySnapshot>,
) {
    if let cat4igp_shared::control::ControlRequest::Enroll(request) = request {
        if request.client_peer_id != peer_id.to_string()
            || request.request_id.len() > 256
            || request.client_encryption_key.len() != 64
            || request.node_name.len() > 256
            || request.invitation_code.is_empty()
            || request.invitation_code.len() > 256
            || request.wireguard_public_key.len() > 256
            || request.client_signing_key.len() > 1024
            || request.node_name.is_empty()
            || request.wireguard_public_key.is_empty()
            || request.client_signing_key.is_empty()
            || request.client_encryption_key.is_empty()
            || !matches!(hex_decode(&request.client_encryption_key), Ok(key) if key.len() == 32)
        {
            return (
                cat4igp_shared::control::ControlResponse::Rejected(
                    "invalid enrollment request".to_string(),
                ),
                Vec::new(),
            );
        }
        match hex_decode(&request.client_signing_key).and_then(|encoded| {
            identity::PublicKey::try_decode_protobuf(&encoded)
                .map_err(|_| "invalid client signing key".to_string())
        }) {
            Ok(key) if key.to_peer_id() == *peer_id => (),
            _ => {
                return (
                    cat4igp_shared::control::ControlResponse::Rejected(
                        "client signing key does not match transport identity".to_string(),
                    ),
                    Vec::new(),
                );
            }
        };
        let controller_encryption_key = match control_encryption_public_key() {
            Ok(key) => key,
            Err(error) => {
                return (
                    cat4igp_shared::control::ControlResponse::Rejected(format!(
                        "controller encryption identity unavailable: {error}"
                    )),
                    Vec::new(),
                );
            }
        };
        use diesel::prelude::*;
        // ponytail: local serialized submission only; replace with committed leader allocation before HA.
        let node_id = crate::schema::nodes::table
            .select(diesel::dsl::max(crate::schema::nodes::id))
            .first::<Option<i32>>(conn)
            .expect("cannot allocate enrollment node ID")
            .unwrap_or(0)
            .checked_add(1)
            .expect("node IDs exhausted");
        let command = crate::db::EnrollmentCommand {
            allocation: crate::db::prepare_enrollment_allocation(conn, &request.invitation_code)
                .expect("cannot allocate enrollment tunnels"),
            request,
            node_id,
            auth_key: uuid::Uuid::new_v4().to_string(),
            applied_at: chrono::Utc::now().naive_utc(),
            response: cat4igp_shared::control::EnrollmentResponse {
                node_id,
                topology_revision: 0,
                network_id: network_id.to_string(),
                controller_signing_key: controller_signing_key.to_string(),
                controller_encryption_key,
            },
        };
        return crate::db::apply_enrollment(conn, &command)
            .unwrap_or_else(|error| panic!("enrollment application storage failure: {error}"));
    }

    let identity = match crate::db::control_identity_for_peer(conn, &peer_id.to_string()) {
        Ok(identity) => identity,
        Err(_) => {
            return (
                cat4igp_shared::control::ControlResponse::Rejected(
                    "unknown control identity".to_string(),
                ),
                Vec::new(),
            );
        }
    };
    match request {
        cat4igp_shared::control::ControlRequest::Snapshot => {
            let response = (|| {
                let snapshot = crate::db::topology_snapshot(
                    conn,
                    identity.node_id,
                    identity.topology_revision,
                )?;
                let encryption_key =
                    crate::db::control_identity_for_node(conn, identity.node_id)?.encryption_key;
                let now = chrono::Utc::now().timestamp_millis();
                cat4igp_shared::control::seal_topology_snapshot(
                    controller_keypair,
                    &encryption_key,
                    cat4igp_shared::control::MessageMeta {
                        message_id: uuid::Uuid::new_v4().simple().to_string(),
                        network_id: network_id.to_string(),
                        recipient_node_id: identity.node_id,
                        issued_at_ms: now,
                        expires_at_ms: now + 60_000,
                        topology_revision: identity.topology_revision,
                    },
                    &snapshot,
                )
                .map(cat4igp_shared::control::ControlResponse::SnapshotEnvelope)
                .map_err(|error| {
                    diesel::result::Error::DeserializationError(Box::new(std::io::Error::other(
                        error,
                    )))
                })
            })();
            (
                response.unwrap_or_else(|error| {
                    cat4igp_shared::control::ControlResponse::Rejected(error.to_string())
                }),
                Vec::new(),
            )
        }
        cat4igp_shared::control::ControlRequest::TunnelAnswerEnvelope(envelope) => {
            let answer = match control_encryption_private_key().and_then(|private_key| {
                cat4igp_shared::control::open_tunnel_answer(
                    &identity.signing_key,
                    &private_key,
                    network_id,
                    identity.node_id,
                    chrono::Utc::now().timestamp_millis(),
                    &envelope,
                )
                .map_err(str::to_string)
            }) {
                Ok(answer) => answer,
                Err(error) => {
                    return (
                        cat4igp_shared::control::ControlResponse::Rejected(error),
                        Vec::new(),
                    );
                }
            };
            let command = crate::db::AnswerCommand {
                node_id: identity.node_id,
                request_id: envelope.meta.message_id,
                answer,
                applied_at: chrono::Utc::now().naive_utc(),
            };
            match crate::db::apply_answer(conn, &command) {
                Ok(result) if result == "accepted" => {
                    match crate::db::tunnel_peer_node_ids(conn, command.answer.tunnel_id) {
                        Ok((peer1, peer2)) => {
                            let snapshots = [peer1, peer2]
                                .into_iter()
                                .filter_map(|node_id| {
                                    let revision =
                                        crate::db::control_identity_for_node(conn, node_id)
                                            .ok()?
                                            .topology_revision;
                                    crate::db::topology_snapshot(conn, node_id, revision).ok()
                                })
                                .collect();
                            (
                                cat4igp_shared::control::ControlResponse::Accepted,
                                snapshots,
                            )
                        }
                        Err(error) => (
                            cat4igp_shared::control::ControlResponse::Rejected(error.to_string()),
                            Vec::new(),
                        ),
                    }
                }
                Ok(result) => (
                    cat4igp_shared::control::ControlResponse::Rejected(result),
                    Vec::new(),
                ),
                Err(error) => panic!("answer application storage failure: {error}"),
            }
        }
        cat4igp_shared::control::ControlRequest::Enroll(_) => unreachable!(),
    }
}

fn hex_decode(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("CONTROL_PRIVATE_KEY must be hexadecimal".to_string());
    }
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn control_keypair() -> Result<identity::Keypair, String> {
    let mut conn = crate::db::establish_connection();
    let candidate = identity::Keypair::generate_ed25519();
    crate::db::apply_initialization(
        &mut conn,
        &crate::db::InitializeCommand {
            signing_private_key: hex_encode(
                &candidate
                    .to_protobuf_encoding()
                    .map_err(|_| "failed to encode controller identity")?,
            ),
            encryption_private_key: hex_encode(
                &x25519_dalek::StaticSecret::random_from_rng(rand08::rngs::OsRng).to_bytes(),
            ),
            network_id: uuid::Uuid::new_v4().to_string(),
            applied_at: chrono::Utc::now().naive_utc(),
        },
    )
    .map_err(|e| e.to_string())?;
    let encoded = match crate::db::get_setting(&mut conn, "control_private_key") {
        Ok(encoded) => encoded,
        Err(error) => return Err(error.to_string()),
    };
    identity::Keypair::from_protobuf_encoding(&hex_decode(&encoded)?)
        .map_err(|_| "stored controller identity is invalid".to_string())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn control_network_id() -> Result<String, String> {
    let mut conn = crate::db::establish_connection();
    match crate::db::get_setting(&mut conn, "control_network_id") {
        Ok(value) if !value.is_empty() => Ok(value),
        Ok(_) => Err("stored control network id is empty".to_string()),
        Err(error) => Err(error.to_string()),
    }
}

fn control_encryption_public_key() -> Result<String, String> {
    let private = control_encryption_private_key()?;
    let private: [u8; 32] = hex_decode(&private)?
        .try_into()
        .map_err(|_| "stored controller encryption identity is invalid")?;
    Ok(hex_encode(
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private)).as_bytes(),
    ))
}

fn control_encryption_private_key() -> Result<String, String> {
    let mut conn = crate::db::establish_connection();
    Ok(
        match crate::db::get_setting(&mut conn, "control_encryption_private_key") {
            Ok(encoded) => encoded,
            Err(error) => return Err(error.to_string()),
        },
    )
}

async fn run_control_plane(
    jobs: DatabaseSender,
    work: tokio::sync::mpsc::Receiver<DatabaseJob>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listen_address = env::var("CONTROL_BIND_MULTIADDR")?;
    let keypair = control_keypair()?;
    let network_id = control_network_id()?;
    let private_network_key: PreSharedKey = env::var("CONTROL_PRIVATE_NETWORK_KEY")
        .map_err(|_| "CONTROL_PRIVATE_NETWORK_KEY must contain a libp2p PSK key file")?
        .parse()
        .map_err(|_| "CONTROL_PRIVATE_NETWORK_KEY is invalid")?;
    eprintln!(
        "[control] controller peer id: {}",
        keypair.public().to_peer_id()
    );
    let transport = tcp::tokio::Transport::new(tcp::Config::default())
        .and_then(move |socket, _| PnetConfig::new(private_network_key).handshake(socket))
        .upgrade(Version::V1)
        .authenticate(noise::Config::new(&keypair)?)
        .multiplex(yamux::Config::default())
        .boxed();
    let mut swarm = Swarm::new(
        transport,
        ControlBehaviour {
            request_response: json::Behaviour::new(
                [(
                    StreamProtocol::new(CONTROL_PROTOCOL),
                    request_response::ProtocolSupport::Full,
                )],
                request_response::Config::default(),
            ),
            gossipsub: gossipsub(&keypair)?,
        },
        keypair.public().to_peer_id(),
        SwarmConfig::with_tokio_executor(),
    );
    swarm.listen_on(listen_address.parse()?)?;

    // ponytail: serialized local SQL, not consensus; replace submission with OpenRaft
    // commit/apply before HA. At most 32 queued + 1 active + 32 completed jobs.
    let (completed, mut results) = tokio::sync::mpsc::channel(DATABASE_QUEUE_CAPACITY);
    let worker_key = keypair.clone();
    let worker_network = network_id.clone();
    let mut worker = tokio::task::spawn_blocking(move || {
        database_worker(
            crate::db::establish_connection(),
            work,
            completed,
            worker_key,
            worker_network,
        );
    });
    loop {
        tokio::select! {
        stopped = &mut worker => return Err(format!("control database worker stopped: {stopped:?}").into()),
        Some((peer, channel, response, pushes)) = results.recv() => {
            if swarm.behaviour_mut().request_response.send_response(channel, response).is_err() {
                eprintln!("[control] failed to respond to {peer}");
            }
            for (node_id, payload) in pushes {
                let topic = gossipsub::Sha256Topic::new(cat4igp_shared::control::topology_topic(&network_id, node_id));
                if let Err(error) = swarm.behaviour_mut().gossipsub.publish(topic, payload) {
                    eprintln!("[control] failed to publish topology for {node_id}: {error}");
                }
            }
        }
        event = swarm.select_next_some() => match event {
            libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } => {
                eprintln!("[control] listening on {address}");
            }
            libp2p::swarm::SwarmEvent::Behaviour(ControlBehaviourEvent::RequestResponse(
                request_response::Event::Message {
                    peer,
                    message:
                        request_response::Message::Request {
                            request, channel, ..
                        },
                    ..
                },
            )) => {
                // Never await queue capacity here: network polling must continue during DB work.
                if let Err(error) = jobs.try_send(DatabaseJob::Control(peer, request, channel)) {
                    let DatabaseJob::Control(peer, _, channel) = error.into_inner() else { unreachable!() };
                    let _ = swarm.behaviour_mut().request_response.send_response(channel,
                        cat4igp_shared::control::ControlResponse::Rejected("control service busy; retry the same request".into()));
                    eprintln!("[control] submission queue unavailable for {peer}");
                }
            }
            _ => {}
        }
        }
    }
}

fn database_worker(
    mut conn: diesel::SqliteConnection,
    mut work: tokio::sync::mpsc::Receiver<DatabaseJob>,
    completed: tokio::sync::mpsc::Sender<ControlCompletion>,
    worker_key: identity::Keypair,
    worker_network: String,
) -> diesel::SqliteConnection {
    while let Some(job) = work.blocking_recv() {
        let (peer, request, channel) = match job {
            DatabaseJob::Control(peer, request, channel) => (peer, request, channel),
            DatabaseJob::Invite {
                request_id,
                expires_at,
                max_uses,
                join_mesh,
                reply,
            } => {
                // A disconnected caller must not cancel a potentially committed write.
                // ponytail: singleton ordered allocation; submit this selected command through OpenRaft before HA.
                let result = (|| {
                    use diesel::prelude::*;
                    let last = crate::schema::invites::table
                        .select(diesel::dsl::max(crate::schema::invites::id))
                        .first::<Option<i32>>(&mut conn)?
                        .unwrap_or(0);
                    let id = last
                        .checked_add(1)
                        .ok_or(diesel::result::Error::RollbackTransaction)?;
                    crate::db::apply_invite(
                        &mut conn,
                        &crate::db::InviteCommand {
                            request_id,
                            id,
                            code: uuid::Uuid::new_v4().to_string(),
                            expires_at,
                            max_uses,
                            join_mesh,
                            applied_at: chrono::Utc::now().naive_utc(),
                        },
                    )
                })();
                let _ = reply.send(result);
                continue;
            }
        };
        let (response, snapshots) = control_response(
            &mut conn,
            &peer,
            &hex_encode(&worker_key.public().encode_protobuf()),
            &worker_key,
            &worker_network,
            request,
        );
        let mut pushes = Vec::new();
        for snapshot in snapshots {
            let identity = crate::db::control_identity_for_node(&mut conn, snapshot.node_id)
                .expect("cannot read committed topology recipient");
            let now = chrono::Utc::now().timestamp_millis();
            let envelope = cat4igp_shared::control::seal_topology_snapshot(
                &worker_key,
                &identity.encryption_key,
                cat4igp_shared::control::MessageMeta {
                    message_id: uuid::Uuid::new_v4().simple().to_string(),
                    network_id: worker_network.clone(),
                    recipient_node_id: snapshot.node_id,
                    issued_at_ms: now,
                    expires_at_ms: now + 60_000,
                    topology_revision: snapshot.revision,
                },
                &snapshot,
            )
            .expect("cannot seal committed topology");
            pushes.push((
                snapshot.node_id,
                serde_json::to_vec(&envelope).expect("cannot serialize topology"),
            ));
        }
        if completed
            .blocking_send((peer, channel, response, pushes))
            .is_err()
        {
            break;
        }
    }
    conn
}

#[tokio::main]
async fn main() -> Result<(), String> {
    dotenv().ok();
    tracing_subscriber::fmt::init();
    let args: Vec<_> = env::args_os().skip(1).collect();
    if args.as_slice() == ["verify-recovery"] {
        if env::var("CLUSTER_MAINTENANCE_STOPPED").as_deref() != Ok("true") {
            return Err("offline verification requires CLUSTER_MAINTENANCE_STOPPED=true".into());
        }
        let required = |name| env::var(name).map_err(|_| format!("{name} required"));
        let report = raft_storage::verify_recovery(
            &required("RECOVERY_FILE")?, &required("RECOVERY_KIND")?,
            &required("DISCOVERY_CLUSTER_ID")?, &required("DISCOVERY_SIGNING_KEY")?,
            &required("RECOVERY_ENCRYPTION_KEY")?,
        ).map_err(|_| "recovery verification rejected: schema, identity, snapshot or consensus inconsistency (no secrets reported)".to_string())?;
        println!("{report}");
        return Ok(());
    }
    if args.as_slice() == ["apply-transport-rotation"] {
        return cluster::offline_transport();
    }
    if args.as_slice() == ["discover-replica"] || args.as_slice() == ["join-replica"] {
        let pin = identity::PublicKey::try_decode_protobuf(&hex_decode(
            &env::var("DISCOVERY_SIGNING_KEY").map_err(
                |_| "DISCOVERY_SIGNING_KEY must be a trusted protobuf public key in hex",
            )?,
        )?)
        .map_err(|e| e.to_string())?;
        let bootstrap = env::var("DISCOVERY_BOOTSTRAP")
            .map_err(|_| "DISCOVERY_BOOTSTRAP must be a trusted IP/TCP/p2p address")?
            .parse()
            .map_err(|_| "invalid discovery bootstrap")?;
        let cluster =
            env::var("DISCOVERY_CLUSTER_ID").map_err(|_| "DISCOVERY_CLUSTER_ID must be set")?;
        let key = if args.as_slice() == ["join-replica"] {
            let identity_path =
                env::var("REPLICA_IDENTITY_FILE").map_err(|_| "REPLICA_IDENTITY_FILE required")?;
            if !std::path::Path::new(&identity_path).is_file() {
                return Err("join requires an existing distinct replica identity".into());
            }
            crate::raft_network::replica_identity(std::path::Path::new(
                &env::var("REPLICA_IDENTITY_FILE").map_err(|_| "REPLICA_IDENTITY_FILE required")?,
            ))
            .map_err(|e| e.to_string())?
        } else {
            identity::Keypair::from_protobuf_encoding(&hex_decode(
            &env::var("DISCOVERY_PRIVATE_KEY").map_err(|_| "DISCOVERY_PRIVATE_KEY must contain the persistent joining transport identity in hex")?,
        )?).map_err(|e| e.to_string())?
        };
        let revision = env::var("DISCOVERY_MINIMUM_REVISION")
            .map_err(|_| "DISCOVERY_MINIMUM_REVISION must be set")?
            .parse()
            .map_err(|_| "invalid discovery minimum revision")?;
        if args.as_slice() == ["join-replica"] {
            let request = cat4igp_shared::discovery::join::Request {
                application_version: cat4igp_shared::discovery::join::APPLICATION_VERSION,
                cluster_id: cluster,
                request_id: env::var("REPLICA_JOIN_REQUEST_ID")
                    .map_err(|_| "stable REPLICA_JOIN_REQUEST_ID required")?,
                node_id: env::var("REPLICA_NODE_ID")
                    .map_err(|_| "REPLICA_NODE_ID required")?
                    .parse()
                    .map_err(|_| "invalid replica NodeId")?,
                address: env::var("REPLICA_ADDRESS")
                    .map_err(|_| "REPLICA_ADDRESS required")?
                    .parse()
                    .map_err(|_| "invalid replica address")?,
                code: env::var("REPLICA_JOIN_CODE").map_err(|_| "REPLICA_JOIN_CODE required")?,
            };
            let response = cat4igp_shared::discovery::join::request(
                &key,
                &pin,
                &[bootstrap],
                revision,
                request.clone(),
            )
            .await?;
            cluster::save_join(
                &env::var("CLUSTER_CONFIG_FILE").map_err(|_| "CLUSTER_CONFIG_FILE required")?,
                env::var("REPLICA_IDENTITY_FILE").map_err(|_| "REPLICA_IDENTITY_FILE required")?,
                env::var("REPLICA_LISTEN_ADDRESS")
                    .map_err(|_| "REPLICA_LISTEN_ADDRESS required")?
                    .parse()
                    .map_err(|_| "invalid learner listen address")?,
                &request,
                &response,
            )?;
            println!(
                "Committed learner bootstrap saved; start server with CLUSTER_CONFIG_FILE, then explicitly activate learner."
            );
            return Ok(());
        }
        let proof = cat4igp_shared::discovery::transport::discover(
            &key,
            &pin,
            &cluster,
            cat4igp_shared::discovery::Role::Replica,
            &[bootstrap],
            revision,
        )
        .await?;
        println!(
            "{}",
            String::from_utf8(cat4igp_shared::discovery::encode(&proof)?)
                .map_err(|e| e.to_string())?
        );
        return Ok(());
    }
    let manual = match args.as_slice() {
        [] => false,
        [command] if command == "migrate" => true,
        _ => return Err("usage: cat4igp-server [migrate|discover-replica|join-replica]".into()),
    };
    let apply = if manual {
        true
    } else {
        match env::var("AUTO_MIGRATE") {
            Err(env::VarError::NotPresent) => true,
            Ok(value) if value == "true" => true,
            Ok(value) if value == "false" => false,
            _ => return Err("AUTO_MIGRATE must be true or false".into()),
        }
    };
    let database_url =
        env::var("DATABASE_URL").map_err(|_| "DATABASE_URL must be set".to_string())?;
    if !manual {
        if let Ok(path) = env::var("CLUSTER_CONFIG_FILE") {
            return cluster::serve(&path, database_url, apply).await;
        }
        if env::var_os("CLUSTER_CONFIG_FILE").is_some() {
            return Err("CLUSTER_CONFIG_FILE must be UTF-8".into());
        }
    }
    let mut conn = diesel::SqliteConnection::establish(&database_url)
        .map_err(|e| format!("Cannot open database: {e}"))?;
    db::configure_connection(&mut conn).map_err(|e| format!("Cannot configure database: {e}"))?;
    db::migrate(&mut conn, apply).map_err(|e| format!("Database migration failed: {e}"))?;
    drop(conn);
    if manual {
        return Ok(());
    }
    let mut conn = diesel::SqliteConnection::establish(&database_url).map_err(|e| e.to_string())?;
    use diesel::RunQueryDsl;
    #[derive(diesel::QueryableByName)]
    struct ClusterCount {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        count: i64,
    }
    let cluster = diesel::sql_query("SELECT count(*) AS count FROM raft_meta WHERE key = 'replica_binding' OR key = 'vote' OR key = 'applied'")
        .get_result::<ClusterCount>(&mut conn).map_err(|e| e.to_string())?;
    if cluster.count != 0 {
        return Err("cluster database cannot run standalone; configure explicit recovery".into());
    }
    drop(conn);
    let (jobs, work) = tokio::sync::mpsc::channel(DATABASE_QUEUE_CAPACITY);
    let app = router::make_router(jobs.clone()).await.unwrap();
    let listener = tokio::net::TcpListener::bind(
        env::var("BIND_HOST_PORT").expect("BIND_HOST_PORT must be set"),
    )
    .await
    .unwrap();
    tokio::select! {
        result = axum::serve(listener, app) => result.unwrap(),
        result = run_control_plane(jobs, work) => return Err(format!("control plane stopped: {result:?}")),
        result = run_discovery() => return Err(format!("discovery stopped: {result}")),
    }
    Ok(())
}

async fn run_discovery() -> String {
    async {
        let path = match env::var("DISCOVERY_ROSTER_FILE") {
            Err(env::VarError::NotPresent) => {
                return std::future::pending::<Result<(), String>>().await;
            }
            Err(error) => return Err(error.to_string()),
            Ok(path) => path,
        };
        // ponytail: operator-signed expiring roster only; replace with committed
        // roster refresh when HA authority exists. No local membership fabrication.
        let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
        let mut bytes = Vec::new();
        use std::io::Read;
        file.take(cat4igp_shared::discovery::MAX_MESSAGE_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        let roster = cat4igp_shared::discovery::decode(&bytes)?;
        let key = control_keypair()?;
        let mut swarm = cat4igp_shared::discovery::transport::swarm(&key)?;
        let listen = env::var("DISCOVERY_LISTEN_ADDRESS")
            .map_err(|_| "DISCOVERY_LISTEN_ADDRESS must be set")?
            .parse()
            .map_err(|_| "invalid discovery listen address")?;
        swarm.listen_on(listen).map_err(|e| e.to_string())?;
        cat4igp_shared::discovery::transport::serve(swarm, key, roster).await
    }
    .await
    .err()
    .unwrap_or_else(|| "unexpected completion".into())
}

#[cfg(test)]
#[path = "main_test.rs"]
mod submission_tests;
