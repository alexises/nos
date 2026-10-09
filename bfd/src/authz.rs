//! Who may call `nos-bfdd` (a pure allow-list, no wildcard arm: a new
//! `BfdRequest` variant must be classified before this compiles).

use nos_proto::{BfdRequest, Role};

pub fn allowed(role: Role, req: &BfdRequest) -> bool {
    match req {
        BfdRequest::Register { .. } | BfdRequest::Deregister { .. } => {
            matches!(role, Role::Bgpd | Role::Ribd | Role::Ospfd | Role::Ospfv3d)
        }
        BfdRequest::GetSessions { .. } | BfdRequest::GetReflector => {
            matches!(role, Role::User | Role::Restd)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nos_proto::{schema::BfdProfile, SessionKey};

    #[test]
    fn every_role_against_every_request() {
        let key = SessionKey {
            aggregate: None,
            table: "rt1".into(),
            peer: "192.0.2.1".parse().unwrap(),
            local: None,
            interface: None,
            multihop: false,
        };
        let reqs = [
            (
                BfdRequest::Register {
                    table: "rt1".into(),
                    peer: key.peer,
                    local: None,
                    interface: None,
                    profile: BfdProfile::default(),
                    multihop: false,
                },
                &[Role::Bgpd, Role::Ribd, Role::Ospfd, Role::Ospfv3d][..],
            ),
            (
                BfdRequest::Deregister { key },
                &[Role::Bgpd, Role::Ribd, Role::Ospfd, Role::Ospfv3d][..],
            ),
            (
                BfdRequest::GetSessions { peer: None },
                &[Role::User, Role::Restd][..],
            ),
            (BfdRequest::GetReflector, &[Role::User, Role::Restd][..]),
        ];
        for (req, ok) in &reqs {
            for role in Role::ALL {
                assert_eq!(allowed(role, req), ok.contains(&role), "{role:?} {req:?}");
            }
        }
    }
}
