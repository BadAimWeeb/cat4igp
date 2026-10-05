use super::*;

#[test]
fn signed_discovery_for_both_roles_fails_closed() {
    let key = identity::Keypair::generate_ed25519();
    let pin = key.public();
    let peer = identity::Keypair::generate_ed25519().public().to_peer_id();
    let requester = identity::Keypair::generate_ed25519().public().to_peer_id();
    let endpoint = ControllerEndpoint {
        peer_id: peer,
        addresses: vec![
            format!("/ip4/127.0.0.1/tcp/9000/p2p/{peer}")
                .parse()
                .unwrap(),
        ],
    };
    let roster = ControllerRoster {
        version: VERSION,
        cluster_id: "test-network".into(),
        revision: 7,
        issued_at_ms: 1000,
        expires_at_ms: 61_000,
        controllers: vec![endpoint.clone()],
        discovery_endpoints: vec![],
    }
    .sign(&key)
    .unwrap();
    assert!(
        !serde_json::to_value(&roster.body)
            .unwrap()
            .as_object()
            .unwrap()
            .contains_key("discovery_endpoints")
    );
    let old: Signed<ControllerRoster> = decode(&encode(&roster).unwrap()).unwrap();
    old.validate(&pin, "test-network", 7, 1001).unwrap();
    let mut unauthorized = roster.body.clone();
    unauthorized.discovery_endpoints.push(ControllerEndpoint {
        peer_id: requester,
        addresses: vec![
            format!("/ip4/127.0.0.1/tcp/9001/p2p/{requester}")
                .parse()
                .unwrap(),
        ],
    });
    assert!(
        unauthorized
            .sign(&key)
            .unwrap()
            .validate(&pin, "test-network", 7, 1001)
            .is_err()
    );
    for role in [Role::Client, Role::Replica] {
        let query = FindControllers::new("test-network".into(), role, requester, 1000).unwrap();
        assert!(
            query
                .validate(requester, "test-network", role, 1001)
                .is_ok()
        );
        assert!(query.validate(peer, "test-network", role, 1001).is_err());
        let body = ControllerAvailable {
            version: VERSION,
            cluster_id: query.cluster_id.clone(),
            role,
            recipient: requester,
            nonce: query.nonce,
            issued_at_ms: 1000,
            expires_at_ms: 31_000,
            endpoint: endpoint.clone(),
            roster: roster.clone(),
        };
        let signed = body.clone().sign(&key).unwrap();
        let bytes = encode(&signed).unwrap();
        let parsed: Signed<ControllerAvailable> = decode(&bytes).unwrap();
        assert_eq!(
            parsed.validate(&pin, &query, peer, 7, 1001).unwrap(),
            &endpoint
        );
        assert!(parsed.validate(&pin, &query, requester, 7, 1001).is_err());
        assert!(parsed.validate(&pin, &query, peer, 8, 1001).is_err());
        assert!(parsed.validate(&pin, &query, peer, 7, 31_000).is_err());
        assert!(
            parsed
                .validate(
                    &identity::Keypair::generate_ed25519().public(),
                    &query,
                    peer,
                    7,
                    1001
                )
                .is_err()
        );
        let mut tampered = parsed.clone();
        tampered.body.nonce[0] ^= 1;
        assert!(tampered.validate(&pin, &query, peer, 7, 1001).is_err());
        for mutation in 0..8 {
            let mut wrong = body.clone();
            match mutation {
                0 => wrong.nonce[0] ^= 1,
                1 => wrong.recipient = peer,
                2 => wrong.cluster_id = "other".into(),
                3 => {
                    wrong.role = if role == Role::Client {
                        Role::Replica
                    } else {
                        Role::Client
                    }
                }
                4 => wrong.expires_at_ms = 31_001,
                5 => {
                    wrong.endpoint.addresses = vec![
                        format!("/ip4/127.0.0.1/tcp/9001/p2p/{peer}")
                            .parse()
                            .unwrap(),
                    ]
                }
                6 => wrong.roster.body.controllers.clear(),
                _ => wrong.issued_at_ms = i64::MIN,
            }
            assert!(
                wrong
                    .sign(&key)
                    .unwrap()
                    .validate(&pin, &query, peer, 7, 1001)
                    .is_err()
            );
        }
        let mut value = serde_json::to_value(&signed).unwrap();
        value["body"]["invitation_code"] = "must-not-be-published".into();
        assert!(
            decode::<Signed<ControllerAvailable>>(&serde_json::to_vec(&value).unwrap()).is_err()
        );
        let text = String::from_utf8(bytes).unwrap();
        for secret in [
            "invitation",
            "join_code",
            "private_network_key",
            "private_key",
            "topology",
        ] {
            assert!(!text.contains(secret));
        }
    }
    assert_ne!(
        topic("test-network", Role::Client).unwrap(),
        topic("test-network", Role::Replica).unwrap()
    );
    assert!(topic("bad/cluster", Role::Client).is_err());
    assert!(decode::<FindControllers>(&vec![b' '; MAX_MESSAGE_BYTES + 1]).is_err());
    assert!(FindControllers::new("test".into(), Role::Client, requester, i64::MAX).is_err());
    assert!(lifetime(i64::MIN, i64::MAX, 0, QUERY_TTL_MS).is_err());
    let mut invalid = roster.body.clone();
    invalid.controllers.push(endpoint);
    assert!(
        invalid
            .sign(&key)
            .unwrap()
            .validate(&pin, "test-network", 7, 1001)
            .is_err()
    );
}
