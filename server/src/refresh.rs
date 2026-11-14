#[cfg(test)]
use base64::{Engine, engine::general_purpose::STANDARD};
use cat4igp_shared::control::{RefreshAnswer, RefreshMode, RefreshOffer, RefreshPending, RefreshStage, RefreshState};
use diesel::{prelude::*, sql_types::Text};
use serde::{Deserialize, Serialize};

#[derive(Clone, Default, Serialize, Deserialize)]
struct Pending {
    generation: u64,
    slot: u8,
    offers: [Option<RefreshOffer>; 2],
    ready: [bool; 2],
    switched: [bool; 2],
    #[serde(default)]
    rolling_back: bool,
    #[serde(default)]
    rolled_back: [bool; 2],
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct State {
    pub mode: RefreshMode,
    active_generation: u64,
    active_slot: u8,
    next_generation: u64,
    active_keys: [Option<String>; 2],
    pending: Option<Pending>,
}
impl Default for State {
    fn default() -> Self {
        Self { mode: RefreshMode::Current, active_generation: 0, active_slot: 0, next_generation: 1, active_keys: [None, None], pending: None }
    }
}
#[derive(QueryableByName)]
struct Value { #[diesel(sql_type = Text)] value: String }
fn json_error(e: serde_json::Error) -> diesel::result::Error { diesel::result::Error::DeserializationError(Box::new(e)) }
pub(crate) fn load(conn: &mut SqliteConnection, id: i32) -> QueryResult<State> {
    let row = diesel::sql_query("SELECT value FROM application_kv WHERE key=?")
        .bind::<Text, _>(format!("wireguard_refresh/{id}"))
        .get_result::<Value>(conn).optional()?;
    row.map(|r| serde_json::from_str(&r.value).map_err(json_error)).unwrap_or_else(|| Ok(State::default()))
}
fn save(conn: &mut SqliteConnection, id: i32, state: &State) -> QueryResult<()> {
    let json = serde_json::to_string(state).map_err(json_error)?;
    diesel::sql_query("INSERT INTO application_kv(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
        .bind::<Text, _>(format!("wireguard_refresh/{id}")) .bind::<Text, _>(json).execute(conn)?;
    Ok(())
}
pub(crate) fn mode_change_allowed(state: &State, mode: RefreshMode) -> bool {
    state.mode == mode || state.pending.is_none()
}
pub(crate) fn set_mode(conn: &mut SqliteConnection, id: i32, mode: RefreshMode) -> QueryResult<Result<(), String>> {
    let mut state = load(conn, id)?;
    if !mode_change_allowed(&state, mode) { return Ok(Err("cannot change mode during a dual-link transition".into())); }
    state.mode = mode;
    save(conn, id, &state)?;
    Ok(Ok(()))
}
pub(crate) fn snapshot(state: &State, first: bool) -> RefreshState {
    let i = usize::from(!first); let j = 1 - i;
    RefreshState {
        active_generation: state.active_generation, active_slot: state.active_slot, next_generation: state.next_generation,
        pending: state.pending.as_ref().map(|p| RefreshPending {
            generation: p.generation, slot: p.slot, local_offer: p.offers[i].clone(), remote_offer: p.offers[j].clone(),
            local_ready: p.ready[i], remote_ready: p.ready[j], committed: p.ready[0] && p.ready[1],
            local_switched: p.switched[i], remote_switched: p.switched[j],
            rolling_back: p.rolling_back, local_rolled_back: p.rolled_back[i], remote_rolled_back: p.rolled_back[j],
        }),
    }
}
pub(crate) fn remote_key(state: &State, first: bool) -> Option<String> {
    state.active_keys[usize::from(first)].clone()
}
pub(crate) fn has_pending(state: &State) -> bool { state.pending.is_some() }

pub(crate) fn apply(conn: &mut SqliteConnection, tunnel: &crate::models::WireguardTunnel, node: i32, answer: &RefreshAnswer, at: chrono::NaiveDateTime) -> QueryResult<Result<(), String>> {
    let mut state = load(conn, tunnel.id)?;
    if state.mode != RefreshMode::DualLink { return Ok(Err("tunnel is not in dual-link mode".into())); }
    if node != tunnel.node_id_peer1 && node != tunnel.node_id_peer2 { return Ok(Err("unauthorized peer".into())); }
    let i = usize::from(node != tunnel.node_id_peer1);
    if answer.stage == RefreshStage::Offer {
        let Some(offer) = &answer.offer else { return Ok(Err("missing refresh offer".into())); };
        let endpoint = offer.endpoint.parse::<std::net::SocketAddr>().ok();
        let valid_endpoint = endpoint.is_some_and(|e| e.port() != 0 && !e.ip().is_unspecified() && !e.ip().is_multicast() && e.is_ipv6() == tunnel.endpoint_ipv6);
        let valid_key = crate::db::valid_wireguard_public_key(&offer.public_key);
        if !valid_endpoint || !valid_key { return Ok(Err("invalid refresh offer".into())); }
        let old_key = match state.active_keys[i].clone() { Some(key) => key, None => crate::db::get_wireguard_pubkey(conn, node)? };
        if offer.public_key == old_key { return Ok(Err("refresh key must be new".into())); }
        let other_node = if i == 0 { tunnel.node_id_peer2 } else { tunnel.node_id_peer1 };
        let other_key = match state.active_keys[1-i].clone() { Some(key) => key, None => crate::db::get_wireguard_pubkey(conn, other_node)? };
        if offer.public_key == other_key { return Ok(Err("refresh key conflicts with active peer".into())); }
        if state.pending.is_none() {
            if tunnel.node_id_peer1 == tunnel.node_id_peer2 || tunnel.peer1_answered != 1 || tunnel.peer2_answered != 1 || tunnel.endpoint_peer1.is_none() || tunnel.endpoint_peer2.is_none() {
                return Ok(Err("both peers must have an active tunnel".into()));
            }
            if answer.generation != state.next_generation || state.next_generation == u64::MAX { return Ok(Err("invalid refresh generation".into())); }
            state.pending = Some(Pending { generation: state.next_generation, slot: 1 - state.active_slot, ..Default::default() });
            state.next_generation += 1;
        }
        let p = state.pending.as_mut().unwrap();
        if p.generation != answer.generation { return Ok(Err("invalid refresh generation".into())); }
        if p.rolling_back { return Ok(Err("refresh is rolling back".into())); }
        if p.offers[i].as_ref().is_some_and(|existing| existing != offer) || p.offers[1-i].as_ref().is_some_and(|other| other.public_key == offer.public_key) {
            return Ok(Err("conflicting refresh offer".into()));
        }
        p.offers[i] = Some(offer.clone());
    } else {
        if answer.offer.is_some() { return Ok(Err("unexpected refresh offer".into())); }
        let Some(p) = state.pending.as_mut() else { return Ok(Err("no refresh in progress".into())); };
        if p.generation != answer.generation { return Ok(Err("invalid refresh generation".into())); }
        match answer.stage {
            RefreshStage::Ready if !p.rolling_back && p.offers.iter().all(Option::is_some) => p.ready[i] = true,
            RefreshStage::Switched if !p.rolling_back && p.ready[0] && p.ready[1] => p.switched[i] = true,
            RefreshStage::Abort if p.rolling_back => (),
            RefreshStage::Abort if p.ready[0] && p.ready[1] => p.rolling_back = true,
            RefreshStage::Abort => { state.pending = None; },
            RefreshStage::RolledBack if p.rolling_back => p.rolled_back[i] = true,
            _ => return Ok(Err("invalid refresh stage".into())),
        }
    }
    if state.pending.as_ref().is_some_and(|p| p.rolling_back && p.rolled_back[0] && p.rolled_back[1]) {
        state.pending = None;
    }
    if state.pending.as_ref().is_some_and(|p| !p.rolling_back && p.switched[0] && p.switched[1]) {
        let p = state.pending.take().unwrap();
        let [Some(a), Some(b)] = p.offers else { return Err(diesel::result::Error::RollbackTransaction); };
        diesel::sql_query("UPDATE wireguard_tunnels SET endpoint_peer1=?,endpoint_peer2=?,updated_at=? WHERE id=?")
            .bind::<Text, _>(&a.endpoint).bind::<Text, _>(&b.endpoint).bind::<diesel::sql_types::Timestamp, _>(at).bind::<diesel::sql_types::Integer, _>(tunnel.id).execute(conn)?;
        state.active_generation = p.generation; state.active_slot = p.slot;
        state.active_keys = [Some(a.public_key), Some(b.public_key)];
    }
    save(conn, tunnel.id, &state)?;
    Ok(Ok(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use diesel::connection::SimpleConnection;

    #[test]
    fn refresh_is_authenticated_staged_and_persistent() {
        let mut conn = SqliteConnection::establish(":memory:").unwrap();
        crate::db::migrate(&mut conn, true).unwrap();
        conn.batch_execute("INSERT INTO wireguard_tunnels(id,node_id_peer1,node_id_peer2,endpoint_ipv6,endpoint_peer1,endpoint_peer2,peer1_answered,peer2_answered) VALUES(1,1,2,0,'192.0.2.1:1000','192.0.2.2:1000',1,1); INSERT INTO application_kv VALUES('wireguard_key/1',json_object('public_key','old1')),('wireguard_key/2',json_object('public_key','old2'));").unwrap();
        set_mode(&mut conn, 1, RefreshMode::DualLink).unwrap().unwrap();
        let tunnel = crate::db::get_wireguard_answers(&mut conn, 1).unwrap().remove(0);
        let at = chrono::Utc::now().naive_utc();
        let answer = |generation, stage, offer| RefreshAnswer { generation, stage, offer };
        let offer = |n: u8| Some(RefreshOffer { endpoint: format!("192.0.2.{n}:2000"), public_key: STANDARD.encode([n; 32]) });
        assert!(apply(&mut conn, &tunnel, 1, &answer(1, RefreshStage::Ready, None), at).unwrap().is_err());
        apply(&mut conn, &tunnel, 1, &answer(1, RefreshStage::Offer, offer(1)), at).unwrap().unwrap();
        assert!(apply(&mut conn, &tunnel, 1, &answer(1, RefreshStage::Offer, offer(3)), at).unwrap().is_err());
        apply(&mut conn, &tunnel, 2, &answer(1, RefreshStage::Offer, offer(2)), at).unwrap().unwrap();
        apply(&mut conn, &tunnel, 1, &answer(1, RefreshStage::Ready, None), at).unwrap().unwrap();
        assert!(apply(&mut conn, &tunnel, 1, &answer(1, RefreshStage::Switched, None), at).unwrap().is_err());
        apply(&mut conn, &tunnel, 2, &answer(1, RefreshStage::Ready, None), at).unwrap().unwrap();
        apply(&mut conn, &tunnel, 1, &answer(1, RefreshStage::Switched, None), at).unwrap().unwrap();
        assert_eq!(crate::db::get_wireguard_answers(&mut conn, 1).unwrap()[0].endpoint_peer1.as_deref(), Some("192.0.2.1:1000"));
        apply(&mut conn, &tunnel, 2, &answer(1, RefreshStage::Switched, None), at).unwrap().unwrap();
        let state = load(&mut conn, 1).unwrap();
        assert_eq!(snapshot(&state, true).active_generation, 1);
        assert_eq!(remote_key(&state, true), Some(STANDARD.encode([2; 32])));
        assert_eq!(crate::db::get_wireguard_answers(&mut conn, 1).unwrap()[0].endpoint_peer1.as_deref(), Some("192.0.2.1:2000"));
        set_mode(&mut conn, 1, RefreshMode::Current).unwrap().unwrap();
        assert_eq!(snapshot(&load(&mut conn, 1).unwrap(), true).active_generation, 1);
        set_mode(&mut conn, 1, RefreshMode::DualLink).unwrap().unwrap();
        let updated = crate::db::get_wireguard_answers(&mut conn, 1).unwrap().remove(0);
        apply(&mut conn, &updated, 1, &answer(2, RefreshStage::Offer, offer(3)), at).unwrap().unwrap();
        apply(&mut conn, &updated, 2, &answer(2, RefreshStage::Abort, None), at).unwrap().unwrap();
        let after_abort = snapshot(&load(&mut conn, 1).unwrap(), true);
        assert_eq!(after_abort.next_generation, 3);
        assert_eq!(after_abort.active_slot, 1);
        assert!(after_abort.pending.is_none());
        assert!(apply(&mut conn, &updated, 1, &answer(2, RefreshStage::Offer, offer(3)), at).unwrap().is_err());
        apply(&mut conn, &updated, 1, &answer(3, RefreshStage::Offer, offer(3)), at).unwrap().unwrap();
        apply(&mut conn, &updated, 2, &answer(3, RefreshStage::Offer, offer(4)), at).unwrap().unwrap();
        apply(&mut conn, &updated, 1, &answer(3, RefreshStage::Ready, None), at).unwrap().unwrap();
        apply(&mut conn, &updated, 2, &answer(3, RefreshStage::Ready, None), at).unwrap().unwrap();
        apply(&mut conn, &updated, 1, &answer(3, RefreshStage::Switched, None), at).unwrap().unwrap();
        apply(&mut conn, &updated, 2, &answer(3, RefreshStage::Abort, None), at).unwrap().unwrap();
        assert!(snapshot(&load(&mut conn, 1).unwrap(), true).pending.unwrap().rolling_back);
        assert!(apply(&mut conn, &updated, 2, &answer(3, RefreshStage::Switched, None), at).unwrap().is_err());
        apply(&mut conn, &updated, 1, &answer(3, RefreshStage::RolledBack, None), at).unwrap().unwrap();
        assert!(snapshot(&load(&mut conn, 1).unwrap(), true).pending.unwrap().local_rolled_back);
        apply(&mut conn, &updated, 2, &answer(3, RefreshStage::RolledBack, None), at).unwrap().unwrap();
        let rolled_back = snapshot(&load(&mut conn, 1).unwrap(), true);
        assert_eq!(rolled_back.active_generation, 1);
        assert_eq!(rolled_back.next_generation, 4);
        assert!(rolled_back.pending.is_none());
        assert_eq!(crate::db::get_wireguard_answers(&mut conn, 1).unwrap()[0].endpoint_peer1.as_deref(), Some("192.0.2.1:2000"));
    }
}
