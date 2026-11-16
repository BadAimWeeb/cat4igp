use super::*;

#[tokio::test(flavor = "current_thread")]
async fn bounded_worker_keeps_executor_responsive_and_preserves_disconnected_writes() {
    use diesel::connection::SimpleConnection;
    let (jobs, work) = tokio::sync::mpsc::channel(DATABASE_QUEUE_CAPACITY);
    let (completed, _results) = tokio::sync::mpsc::channel(DATABASE_QUEUE_CAPACITY);
    let (release, gate) = std::sync::mpsc::channel();
    let (started, ready) = tokio::sync::oneshot::channel();
    let worker = tokio::task::spawn_blocking(move || {
        let mut conn = diesel::SqliteConnection::establish(":memory:").unwrap();
        crate::db::migrate(&mut conn, true).unwrap();
        // Represent a stalled SQL call without relying on wall-clock sleeps.
        started.send(()).unwrap();
        gate.recv().unwrap();
        let mut conn = database_worker(
            conn,
            work,
            completed,
            identity::Keypair::generate_ed25519(),
            "test".into(),
        );
        assert_eq!(
            crate::db::get_invites(&mut conn).unwrap().len(),
            DATABASE_QUEUE_CAPACITY + 1
        );
    });
    ready.await.unwrap();
    let mut replies = Vec::new();
    for _ in 0..DATABASE_QUEUE_CAPACITY {
        let (reply, result) = tokio::sync::oneshot::channel();
        assert!(
            jobs.try_send(DatabaseJob::Invite {
                request_id: uuid::Uuid::new_v4().to_string(),
                expires_at: None,
                max_uses: Some(1),
                join_mesh: None,
                reply,
            })
            .is_ok()
        );
        replies.push(result);
    }
    let payload = || {
        axum::Json(cat4igp_shared::rest::operator::CreateInvitePayload {
            expires_at: None,
            max_uses: Some(1),
            join_mesh: None,
        })
    };
    let overloaded = router::operator::create_invite(
        axum::extract::State(jobs.clone()),
        axum::http::HeaderMap::new(),
        payload(),
    )
    .await;
    assert!(matches!(
        overloaded,
        Err((axum::http::StatusCode::SERVICE_UNAVAILABLE, _))
    ));
    // Even a single-thread executor continues polling while the worker is blocked.
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        tokio::task::yield_now().await;
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    })
    .await
    .unwrap();
    drop(replies.remove(0));
    release.send(()).unwrap();
    for result in replies {
        assert!(result.await.unwrap().unwrap().is_ok());
    }
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("Idempotency-Key", "route-retry".parse().unwrap());
    let original = router::operator::create_invite(
        axum::extract::State(jobs.clone()),
        headers.clone(),
        payload(),
    )
    .await
    .ok()
    .unwrap()
    .0
    .invite_code;
    let retry = router::operator::create_invite(
        axum::extract::State(jobs.clone()),
        headers.clone(),
        payload(),
    )
    .await
    .ok()
    .unwrap()
    .0
    .invite_code;
    assert_eq!(original, retry);
    let conflict = router::operator::create_invite(
        axum::extract::State(jobs.clone()),
        headers,
        axum::Json(cat4igp_shared::rest::operator::CreateInvitePayload {
            expires_at: None,
            max_uses: Some(2),
            join_mesh: None,
        }),
    )
    .await;
    assert!(matches!(
        conflict,
        Err((axum::http::StatusCode::CONFLICT, _))
    ));
    drop(jobs);
    worker.await.unwrap();

    // SQL failure is reported, and the worker closing drops pending reply senders.
    let (jobs, work) = tokio::sync::mpsc::channel(1);
    let (reply, result) = tokio::sync::oneshot::channel();
    assert!(
        jobs.try_send(DatabaseJob::Invite {
            request_id: uuid::Uuid::new_v4().to_string(),
            expires_at: None,
            max_uses: None,
            join_mesh: None,
            reply,
        })
        .is_ok()
    );
    drop(jobs);
    let (completed, _results) = tokio::sync::mpsc::channel(1);
    tokio::task::spawn_blocking(move || {
        let mut conn = diesel::SqliteConnection::establish(":memory:").unwrap();
        conn.batch_execute("CREATE TABLE unrelated (id INTEGER);")
            .unwrap();
        database_worker(
            conn,
            work,
            completed,
            identity::Keypair::generate_ed25519(),
            "test".into(),
        );
    })
    .await
    .unwrap();
    assert!(result.await.unwrap().is_err());
    let (jobs, work) = tokio::sync::mpsc::channel(1);
    let (reply, result) = tokio::sync::oneshot::channel();
    assert!(
        jobs.try_send(DatabaseJob::Invite {
            request_id: uuid::Uuid::new_v4().to_string(),
            expires_at: None,
            max_uses: None,
            join_mesh: None,
            reply,
        })
        .is_ok()
    );
    let failed = tokio::task::spawn_blocking(move || {
        let _work = work;
        panic!("injected database worker failure");
    })
    .await;
    assert!(failed.unwrap_err().is_panic());
    assert!(result.await.is_err());
    assert!(jobs.is_closed());
    let (jobs, work) = tokio::sync::mpsc::channel(1);
    drop(work);
    let unavailable = router::operator::create_invite(
        axum::extract::State(jobs),
        axum::http::HeaderMap::new(),
        payload(),
    )
    .await;
    assert!(matches!(
        unavailable,
        Err((axum::http::StatusCode::SERVICE_UNAVAILABLE, _))
    ));
}

#[test]
fn fresh_network_rejects_old_control_peer_and_unused_invitation() {
    use cat4igp_shared::control::{ControlRequest, ControlResponse, EnrollmentRequest, EnrollmentResponse};
    use diesel::connection::SimpleConnection;

    // Handler-level boundary evidence only: no live cutover, host fencing,
    // trusted-bundle redistribution or data-plane recovery is claimed here.
    let mut old = diesel::SqliteConnection::establish(":memory:").unwrap();
    let mut fresh = diesel::SqliteConnection::establish(":memory:").unwrap();
    crate::db::migrate(&mut old, true).unwrap();
    crate::db::migrate(&mut fresh, true).unwrap();
    let old_controller = identity::Keypair::generate_ed25519();
    let fresh_controller = identity::Keypair::generate_ed25519();
    let at = chrono::Utc::now().naive_utc();
    for (conn, controller, network) in [
        (&mut old, &old_controller, "old-network"),
        (&mut fresh, &fresh_controller, "fresh-network"),
    ] {
        crate::db::apply_initialization(conn, &crate::db::InitializeCommand {
            signing_private_key: hex_encode(&controller.to_protobuf_encoding().unwrap()),
            encryption_private_key: hex_encode(&x25519_dalek::StaticSecret::random_from_rng(rand08::rngs::OsRng).to_bytes()),
            network_id: network.into(), applied_at: at,
        }).unwrap();
    }
    assert_ne!(old_controller.public().to_peer_id(), fresh_controller.public().to_peer_id());
    old.batch_execute("INSERT INTO invites(code,max_uses) VALUES('old-enrollment',1),('old-unused',1);").unwrap();
    let client = identity::Keypair::generate_ed25519();
    let peer = client.public().to_peer_id();
    let encryption = x25519_dalek::StaticSecret::random_from_rng(rand08::rngs::OsRng);
    let request = EnrollmentRequest {
        request_id: "old-request".into(), node_name: "old-client".into(),
        invitation_code: "old-enrollment".into(), client_peer_id: peer.to_string(),
        client_signing_key: hex_encode(&client.public().encode_protobuf()),
        client_encryption_key: hex_encode(x25519_dalek::PublicKey::from(&encryption).as_bytes()),
        wireguard_public_key: "CQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
    };
    let fresh_signing = hex_encode(&fresh_controller.public().encode_protobuf());
    let old_signing = hex_encode(&old_controller.public().encode_protobuf());
    let command = |conn: &mut diesel::SqliteConnection, request: EnrollmentRequest, network: &str, signing: &str| {
        let private: [u8; 32] = hex_decode(&crate::db::get_setting(conn, "control_encryption_private_key").unwrap()).unwrap().try_into().unwrap();
        let encryption_key = hex_encode(x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private)).as_bytes());
        crate::db::EnrollmentCommand {
            allocation: crate::db::prepare_enrollment_allocation(conn, &request.invitation_code).unwrap(),
            request, node_id: crate::db::next_management_id(conn, "node").unwrap(),
            auth_key: "test-auth".into(), applied_at: at,
            response: EnrollmentResponse {
                node_id: 1, topology_revision: 0, network_id: network.into(),
                controller_signing_key: signing.into(),
                controller_encryption_key: encryption_key,
            },
        }
    };
    let old_command = command(&mut old, request.clone(), "old-network", &old_signing);
    assert!(matches!(crate::db::apply_enrollment(&mut old, &old_command).unwrap().0, ControlResponse::Enrolled(_)));
    let old_identity = crate::db::control_identity_for_peer(&mut old, &peer.to_string()).unwrap();
    let old_revision = old_identity.topology_revision;
    let (response, pushes) = control_response(&mut fresh, &peer, &fresh_signing, &fresh_controller,
        "fresh-network", ControlRequest::Snapshot);
    assert!(matches!(response, ControlResponse::Rejected(reason) if reason == "unknown control identity"));
    assert!(pushes.is_empty());
    let mut old_invite_request = request;
    old_invite_request.request_id = "fresh-request-with-old-invite".into();
    old_invite_request.invitation_code = "old-unused".into();
    let fresh_command = command(&mut fresh, old_invite_request, "fresh-network", &fresh_signing);
    let (response, pushes) = crate::db::apply_enrollment(&mut fresh, &fresh_command).unwrap();
    assert!(matches!(response, ControlResponse::Rejected(reason) if reason == "enrollment rejected"));
    assert!(pushes.is_empty());
    assert!(crate::db::get_node_list(&mut fresh).unwrap().is_empty());
    assert!(crate::db::get_invites(&mut fresh).unwrap().is_empty());
    assert!(crate::db::control_identity_for_peer(&mut fresh, &peer.to_string()).is_err());
    assert_eq!(crate::db::control_identity_for_peer(&mut old, &peer.to_string()).unwrap().topology_revision, old_revision);
    assert_eq!(crate::db::get_invites(&mut old).unwrap().iter().find(|invite| invite.code == "old-unused").unwrap().used_count, 0);
}
