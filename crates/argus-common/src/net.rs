use std::net::IpAddr;

pub fn ip_in_cidr(ip: IpAddr, cidr: &str) -> bool {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return false;
    }
    let prefix_len: u32 = match parts[1].parse() {
        Ok(n) => n,
        Err(_) => return false,
    };
    let net_ip: IpAddr = match parts[0].parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };
    match (ip, net_ip) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => {
            if prefix_len > 32 {
                return false;
            }
            let ip_bits = u32::from(ip);
            let net_bits = u32::from(net);
            let mask = if prefix_len == 0 {
                0
            } else {
                u32::MAX.wrapping_shl(32u32.saturating_sub(prefix_len))
            };
            (ip_bits & mask) == (net_bits & mask)
        }
        (IpAddr::V6(ip), IpAddr::V6(net)) => {
            if prefix_len > 128 {
                return false;
            }
            let ip_bits = u128::from(ip);
            let net_bits = u128::from(net);
            let mask = if prefix_len == 0 {
                0
            } else {
                u128::MAX.wrapping_shl(128u32.saturating_sub(prefix_len))
            };
            (ip_bits & mask) == (net_bits & mask)
        }
        _ => false,
    }
}

pub fn proto_matches(protocol: u8, proto_str: &str) -> bool {
    match proto_str.to_lowercase().as_str() {
        "tcp" => protocol == 6,
        "udp" => protocol == 17,
        "icmp" => protocol == 1,
        "icmpv6" => protocol == 58,
        "any" => true,
        _ => {
            if let Ok(n) = proto_str.parse::<u8>() {
                protocol == n
            } else {
                false
            }
        }
    }
}

pub fn validate_cidr(cidr: &str) -> Result<(), String> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(format!("Invalid CIDR format: {}", cidr));
    }
    let ip: IpAddr = parts[0]
        .parse()
        .map_err(|_| format!("Invalid IP in CIDR: {}", cidr))?;
    let prefix: u32 = parts[1]
        .parse()
        .map_err(|_| format!("Invalid prefix in CIDR: {}", cidr))?;
    match ip {
        IpAddr::V4(_) if prefix > 32 => {
            return Err(format!("IPv4 prefix must be <= 32, got {}", prefix));
        }
        IpAddr::V6(_) if prefix > 128 => {
            return Err(format!("IPv6 prefix must be <= 128, got {}", prefix));
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_in_cidr_v4() {
        assert!(ip_in_cidr("10.0.0.1".parse().unwrap(), "10.0.0.0/8"));
        assert!(!ip_in_cidr("11.0.0.1".parse().unwrap(), "10.0.0.0/8"));
        assert!(ip_in_cidr("1.2.3.4".parse().unwrap(), "0.0.0.0/0"));
        assert!(ip_in_cidr("10.0.0.0".parse().unwrap(), "10.0.0.0/32"));
        assert!(!ip_in_cidr("10.0.0.1".parse().unwrap(), "10.0.0.0/32"));
    }

    #[test]
    fn test_ip_in_cidr_v6() {
        assert!(ip_in_cidr("2001:db8::1".parse().unwrap(), "2001:db8::/32"));
        assert!(!ip_in_cidr("2001:db9::1".parse().unwrap(), "2001:db8::/32"));
    }

    #[test]
    fn test_proto_matches() {
        assert!(proto_matches(6, "tcp"));
        assert!(proto_matches(17, "udp"));
        assert!(proto_matches(1, "icmp"));
        assert!(proto_matches(99, "any"));
        assert!(proto_matches(99, "99"));
        assert!(!proto_matches(6, "udp"));
    }

    #[test]
    fn test_validate_cidr() {
        assert!(validate_cidr("10.0.0.0/8").is_ok());
        assert!(validate_cidr("::1/128").is_ok());
        assert!(validate_cidr("10.0.0.0/33").is_err());
        assert!(validate_cidr("10.0.0.0").is_err());
        assert!(validate_cidr("not-an-ip/8").is_err());
    }
}
