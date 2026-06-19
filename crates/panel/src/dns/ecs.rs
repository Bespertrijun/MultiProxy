//! ECS (EDNS Client Subnet) extraction + scope echo (Line C task 2 / AC-6).
//!
//! Reads `ClientSubnet` from the request EDNS (`addr/source_prefix/scope_prefix`);
//! when ECS is absent the caller falls back to the recursor source IP. The response
//! echoes the ECS **scope prefix** so recursors cache per-subnet correctly.

use std::net::IpAddr;

use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};

/// The client-network view used to geolocate a query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientNetwork {
    /// The address to geolocate (ECS subnet address, or recursor source IP).
    pub addr: IpAddr,
    /// ECS source prefix length if the query carried ECS; `None` for source-IP fallback.
    pub ecs_source_prefix: Option<u8>,
}

/// Extract the ECS subnet from a request's parsed EDNS, if present.
#[must_use]
pub fn ecs_from_edns(edns: Option<&hickory_proto::op::Edns>) -> Option<ClientSubnet> {
    let edns = edns?;
    match edns.option(EdnsCode::Subnet) {
        Some(EdnsOption::Subnet(cs)) => Some(*cs),
        _ => None,
    }
}

/// Resolve the [`ClientNetwork`] for a query: prefer ECS, else fall back to the
/// recursor source IP.
#[must_use]
pub fn client_network(ecs: Option<&ClientSubnet>, src_ip: IpAddr) -> ClientNetwork {
    match ecs {
        Some(cs) => ClientNetwork {
            addr: cs.addr(),
            ecs_source_prefix: Some(cs.source_prefix()),
        },
        None => ClientNetwork {
            addr: src_ip,
            ecs_source_prefix: None,
        },
    }
}

/// Build the ECS option to echo in the response. Per RFC 7871 an authoritative
/// server echoes the query's address + source prefix and sets the **scope prefix**
/// to the prefix length over which the answer is valid. We set scope = source prefix
/// (the answer is specific to the queried subnet).
#[must_use]
pub fn echo_scope(query_ecs: &ClientSubnet) -> ClientSubnet {
    let mut echoed = ClientSubnet::new(
        query_ecs.addr(),
        query_ecs.source_prefix(),
        query_ecs.source_prefix(),
    );
    echoed.set_scope_prefix(query_ecs.source_prefix());
    echoed
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn client_network_prefers_ecs() {
        let cs = ClientSubnet::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 0)), 24, 0);
        let net = client_network(Some(&cs), IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)));
        assert_eq!(net.addr, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 0)));
        assert_eq!(net.ecs_source_prefix, Some(24));
    }

    #[test]
    fn client_network_falls_back_to_src() {
        let net = client_network(None, IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)));
        assert_eq!(net.addr, IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)));
        assert_eq!(net.ecs_source_prefix, None);
    }

    #[test]
    fn scope_echo_sets_scope_to_source() {
        let cs = ClientSubnet::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 0)), 24, 0);
        let echoed = echo_scope(&cs);
        assert_eq!(echoed.scope_prefix(), 24);
        assert_eq!(echoed.source_prefix(), 24);
        assert_eq!(echoed.addr(), IpAddr::V4(Ipv4Addr::new(1, 2, 3, 0)));
    }
}
