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
