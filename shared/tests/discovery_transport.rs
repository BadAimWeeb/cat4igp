use cat4igp_shared::discovery::{ControllerEndpoint, ControllerRoster, Role, VERSION, transport};
use futures_util::StreamExt;
use libp2p::{identity, multiaddr::Protocol, swarm::SwarmEvent};

#[tokio::test]
async fn both_roles_discover_through_noise_and_pubsub() {
    let key = identity::Keypair::generate_ed25519();
    let pin = key.public();
    let peer = pin.to_peer_id();
    let mut server = transport::swarm(&key).unwrap();
    server
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    let bootstrap = loop {
        if let SwarmEvent::NewListenAddr { address, .. } = server.select_next_some().await {
            break address.with(Protocol::P2p(peer));
        }
    };
    let time = chrono::Utc::now().timestamp_millis();
    let roster = ControllerRoster {
        version: VERSION,
        cluster_id: "live-test".into(),
        revision: 4,
        issued_at_ms: time,
        expires_at_ms: time + 60_000,
        discovery_endpoints: vec![],
        controllers: vec![ControllerEndpoint {
            peer_id: peer,
            addresses: vec![bootstrap.clone()],
        }],
    }
    .sign(&key)
    .unwrap();
    let task = tokio::spawn(transport::serve(server, key, roster));
    for role in [Role::Client, Role::Replica] {
        let requester = identity::Keypair::generate_ed25519();
        let proof =
            transport::discover(&requester, &pin, "live-test", role, &[bootstrap.clone()], 4)
                .await
                .unwrap();
        assert_eq!(proof.body.role, role);
        assert_eq!(proof.body.endpoint.peer_id, peer);
        assert_eq!(proof.body.recipient, requester.public().to_peer_id());
    }
    task.abort();
}

#[tokio::test]
async fn untrusted_pin_and_unavailable_bootstrap_fail_without_fallback() {
    let key = identity::Keypair::generate_ed25519();
    let pin = key.public();
    let peer = pin.to_peer_id();
    let mut server = transport::swarm(&key).unwrap();
    server
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    let bootstrap = loop {
        if let SwarmEvent::NewListenAddr { address, .. } = server.select_next_some().await {
            break address.with(Protocol::P2p(peer));
        }
    };
    let time = chrono::Utc::now().timestamp_millis();
    let roster = ControllerRoster {
        version: VERSION,
        cluster_id: "live-test".into(),
        revision: 4,
        issued_at_ms: time,
        expires_at_ms: time + 60_000,
        discovery_endpoints: vec![],
        controllers: vec![ControllerEndpoint {
            peer_id: peer,
            addresses: vec![bootstrap.clone()],
        }],
    }
    .sign(&key)
    .unwrap();
    let task = tokio::spawn(transport::serve(server, key.clone(), roster));
    let wrong_pin = identity::Keypair::generate_ed25519().public();
    let requester = identity::Keypair::generate_ed25519();
    assert!(
        transport::discover(
            &requester,
            &wrong_pin,
            "live-test",
            Role::Replica,
            &[bootstrap.clone()],
            4
        )
        .await
        .is_err()
    );
    task.abort();
    let requester = identity::Keypair::generate_ed25519();
    assert!(
        transport::discover(&requester, &pin, "live-test", Role::Client, &[bootstrap], 4)
            .await
            .is_err()
    );
    assert!(
        transport::discover(
            &requester,
            &pin,
            "live-test",
            Role::Client,
            &["/ip4/127.0.0.1/tcp/9000".parse().unwrap()],
            4
        )
        .await
        .is_err()
    );
}
