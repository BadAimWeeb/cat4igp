//! Experimental epoch-range helpers; they do not establish rolling compatibility.
//! Raft RPCs, snapshots, and persisted state currently require the exact epoch.

/// The application protocol epoch this binary implements.
pub const APPLICATION_VERSION: u8 = 6;

/// Experimental range used to validate window metadata, not wire admission.
pub const BACKWARD_COMPAT: u8 = 1;

/// Lowest epoch recognized by the experimental window metadata.
pub const MIN_SUPPORTED_VERSION: u8 =
    if APPLICATION_VERSION > BACKWARD_COMPAT { APPLICATION_VERSION - BACKWARD_COMPAT } else { 1 };

/// True when `observed` falls within the experimental range.
pub fn wire_compatible(observed: u8) -> bool {
    (MIN_SUPPORTED_VERSION..=APPLICATION_VERSION).contains(&observed)
}

/// Pairwise compatibility for a directional exchange. `local` is the receiver's
/// epoch, `peer` the sender's as stamped on the request. Sync flows only
/// downward (new reads old) or within the same epoch; an old receiver never
/// accepts a newer peer.
pub fn sync_compatible(local: u8, peer: u8) -> bool {
    local >= peer && wire_compatible(peer) && wire_compatible(local)
}

/// Refuse the first not-yet-replayed entry when replay crosses epochs. The
/// caller supplies the last observed wire epoch and the incoming one.
pub fn replay_step(prev: Option<u8>, next: u8) -> bool {
    match prev {
        None => wire_compatible(next),
        Some(previous) => sync_compatible(previous, next),
    }
}
