use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub enum WireguardAnswered {
    Unanswered = 0,
    Answered = 1,
    RejectedGeneric = 2,
    RejectedNoIpStack = 3,
    Unknown = -1
}

impl From<i16> for WireguardAnswered {
    fn from(value: i16) -> Self {
        match value {
            0 => WireguardAnswered::Unanswered,
            1 => WireguardAnswered::Answered,
            2 => WireguardAnswered::RejectedGeneric,
            3 => WireguardAnswered::RejectedNoIpStack,
            _ => WireguardAnswered::Unknown,
        }
    }
}

impl From<WireguardAnswered> for i16 {
    fn from(answered: WireguardAnswered) -> Self {
        match answered {
            WireguardAnswered::Unanswered => 0,
            WireguardAnswered::Answered => 1,
            WireguardAnswered::RejectedGeneric => 2,
            WireguardAnswered::RejectedNoIpStack => 3,
            WireguardAnswered::Unknown => -1,
        }
    }
}
