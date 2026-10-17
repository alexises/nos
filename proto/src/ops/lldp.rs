use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::schema::Config;

use super::OpError;

/// An edit to the system-wide `Config.lldp` settings. A singleton, so there is
/// no name to look up and nothing here can fail structurally.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LldpOp {
    /// Sets the transmit interval of the global LLDP settings to `secs`.
    SetTxInterval {
        /// Interval between LLDPDUs in seconds.
        secs: u16,
    },
    /// Clears the transmit interval of the global LLDP settings so it reverts to the default.
    ClearTxInterval,
    /// Sets the transmit hold of the global LLDP settings to `hold`.
    SetTxHold {
        /// Hold multiplier: TTL = transmit interval x this value.
        hold: u8,
    },
    /// Clears the transmit hold of the global LLDP settings so it reverts to the default.
    ClearTxHold,
    /// Adds one address; adding one already listed does nothing.
    AddManagementAddress {
        /// Management address advertised in the Management Address TLV.
        address: IpAddr,
    },
    /// Clears every address.
    ClearManagementAddress,
    /// Removes management address `address` from the global LLDP settings.
    RemoveManagementAddress {
        /// Management address advertised in the Management Address TLV.
        address: IpAddr,
    },
    /// Sets the System Description TLV text.
    SetSystemDescription {
        /// The text; checked at commit.
        text: String,
    },
    /// Clears the System Description so it reverts to the default.
    ClearSystemDescription,
}

impl LldpOp {
    /// Applies this edit to `config`; fails with an `OpError` when its target is missing.
    pub fn apply(&self, config: &mut Config) -> Result<(), OpError> {
        let lldp = &mut config.lldp;
        match self {
            LldpOp::SetTxInterval { secs } => lldp.tx_interval_secs = Some(*secs),
            LldpOp::ClearTxInterval => lldp.tx_interval_secs = None,
            LldpOp::SetTxHold { hold } => lldp.tx_hold = Some(*hold),
            LldpOp::ClearTxHold => lldp.tx_hold = None,
            LldpOp::AddManagementAddress { address } => {
                if !lldp.management_addresses.contains(address) {
                    lldp.management_addresses.push(*address);
                }
            }
            LldpOp::ClearManagementAddress => lldp.management_addresses.clear(),
            LldpOp::RemoveManagementAddress { address } => {
                lldp.management_addresses.retain(|a| a != address);
            }
            LldpOp::SetSystemDescription { text } => lldp.system_description = Some(text.clone()),
            LldpOp::ClearSystemDescription => lldp.system_description = None,
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
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "2001:db8::1".parse().unwrap();
        for address in [a, b, a] {
            LldpOp::AddManagementAddress { address }
                .apply(&mut cfg)
                .unwrap();
        }
        assert_eq!(cfg.lldp.effective_ttl_secs(), 15);
        assert_eq!(cfg.lldp.management_addresses, [a, b]);
        LldpOp::RemoveManagementAddress { address: a }
            .apply(&mut cfg)
            .unwrap();
        assert_eq!(cfg.lldp.management_addresses, [b]);

        LldpOp::SetSystemDescription { text: "x".into() }
            .apply(&mut cfg)
            .unwrap();
        assert_eq!(cfg.lldp.effective_system_description(), "x");
        LldpOp::ClearSystemDescription.apply(&mut cfg).unwrap();
        LldpOp::ClearTxInterval.apply(&mut cfg).unwrap();
        LldpOp::ClearTxHold.apply(&mut cfg).unwrap();
        LldpOp::ClearManagementAddress.apply(&mut cfg).unwrap();
        assert_eq!(cfg.lldp, crate::schema::LldpSettings::default());
    }
}
