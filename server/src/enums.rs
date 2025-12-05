pub enum WireguardAnswered {
    Unanswered = 0,
    Answered = 1,
    RejectedGeneric = 2,
    RejectedNoIpStack = 3,
}

impl TryFrom<i16> for WireguardAnswered {
    type Error = ();

    fn try_from(value: i16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(WireguardAnswered::Unanswered),
            1 => Ok(WireguardAnswered::Answered),
            2 => Ok(WireguardAnswered::RejectedGeneric),
            3 => Ok(WireguardAnswered::RejectedNoIpStack),
            _ => Err(()),
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
        }
    }
}
