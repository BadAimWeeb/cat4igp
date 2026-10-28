//! Application-epoch compatibility for rolling upgrades.
//!
//! A binary built for epoch N accepts peers running epoch N-1 during an explicit
//! upgrade window. Everything else (older or newer epochs) is rejected exactly as
//! before. Compatibility is one direction only: `N understands N-1`, never the
//! reverse. `sync_compatible(old, new)` encodes that rule for request/response
//! checks; it is asymmetric because the peers took different roles on the wire.
//!
//! Snapshots and persisted state remain epoch-exact. The window is transient and
//! closed by committing `EpochWindow` state through the replicated write path.

/// The application protocol epoch this binary implements.
pub const APPLICATION_VERSION: u8 = 4;

/// Number of epochs a binary tolerates while rolling forward. Only one cohort
/// step is supported, so this stays 1 and the window is [N-1, N].
pub const BACKWARD_COMPAT: u8 = 1;

/// Emit the lowest epoch this binary accepts on the wire. For epoch below 1
/// (nothing sensible) this collapses to 1.
pub const MIN_SUPPORTED_VERSION: u8 =
    if APPLICATION_VERSION > BACKWARD_COMPAT { APPLICATION_VERSION - BACKWARD_COMPAT } else { 1 };

/// True when `observed` is an epoch this binary can talk to (its own or one lower).
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
