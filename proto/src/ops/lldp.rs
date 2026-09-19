use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::schema::Config;

use super::OpError;

/// An edit to the system-wide `Config.lldp` settings. A singleton, so there is
/// no name to look up and nothing here can fail structurally.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LldpOp {
    SetTxInterval { secs: u16 },
    ClearTxInterval,
    SetTxHold { hold: u8 },
    ClearTxHold,
    SetManagementAddress { address: IpAddr },
    ClearManagementAddress,
}

impl LldpOp {
    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        let lldp = &mut config.lldp;
        match self {
            LldpOp::SetTxInterval { secs } => lldp.tx_interval_secs = Some(*secs),
            LldpOp::ClearTxInterval => lldp.tx_interval_secs = None,
            LldpOp::SetTxHold { hold } => lldp.tx_hold = Some(*hold),
            LldpOp::ClearTxHold => lldp.tx_hold = None,
            LldpOp::SetManagementAddress { address } => lldp.management_address = Some(*address),
            LldpOp::ClearManagementAddress => lldp.management_address = None,
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_and_clear_each_field() {
        let mut cfg = Config::default();
        LldpOp::SetTxInterval { secs: 5 }.apply(&mut cfg).unwrap();
        LldpOp::SetTxHold { hold: 3 }.apply(&mut cfg).unwrap();
        LldpOp::SetManagementAddress {
            address: "10.0.0.1".parse().unwrap(),
        }
        .apply(&mut cfg)
        .unwrap();
        assert_eq!(cfg.lldp.effective_ttl_secs(), 15);
        assert_eq!(
            cfg.lldp.management_address,
            Some("10.0.0.1".parse().unwrap())
        );

        LldpOp::ClearTxInterval.apply(&mut cfg).unwrap();
        LldpOp::ClearTxHold.apply(&mut cfg).unwrap();
        LldpOp::ClearManagementAddress.apply(&mut cfg).unwrap();
        assert_eq!(cfg.lldp, crate::schema::LldpSettings::default());
    }
}
