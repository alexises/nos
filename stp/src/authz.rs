//! Who may call `nos-stpd` (a pure allow-list, no wildcard arm: a new
//! `StpRequest` variant must be classified before this compiles).

use nos_proto::{Role, StpRequest};

pub fn allowed(role: Role, req: &StpRequest) -> bool {
    match req {
        StpRequest::GetSummary => matches!(role, Role::User | Role::Restd),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_people_and_restd_may_query() {
        for role in Role::ALL {
            assert_eq!(
                allowed(role, &StpRequest::GetSummary),
                matches!(role, Role::User | Role::Restd),
                "{role:?}"
            );
        }
    }
}
