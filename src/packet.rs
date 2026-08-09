use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use crate::model::{Direction, FlowKey, TransportProtocol};

pub const LINKTYPE_ETHERNET: i32 = 1;
pub const LINKTYPE_RAW: i32 = 101;
pub const LINKTYPE_LINUX_SLL: i32 = 113;
pub const LINKTYPE_LINUX_SLL2: i32 = 276;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketMeta {
    pub timestamp: u64,
    pub wire_bytes: u64,
    pub key: FlowKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketError {
    UnsupportedLinkType(i32),
    Truncated(&'static str),
    Invalid(&'static str),
}

struct IpPacket {
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    ports: Option<(u16, u16)>,
}

impl fmt::Display for PacketError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedLinkType(link_type) => {
                write!(formatter, "unsupported pcap link type {link_type}")
            }
            Self::Truncated(layer) => write!(formatter, "truncated {layer} header"),
            Self::Invalid(layer) => write!(formatter, "invalid {layer} header"),
        }
    }
}

impl std::error::Error for PacketError {}

pub fn parse_packet(
    frame: &[u8],
    link_type: i32,
    timestamp: u64,
    wire_bytes: u64,
    capture_point: &str,
    local_ips: &[IpAddr],
) -> Result<Option<PacketMeta>, PacketError> {
    let (ip_offset, ether_type) = ip_offset(frame, link_type)?;
    let packet = match ether_type {
        0x0800 => parse_ipv4(frame, ip_offset)?,
        0x86dd => parse_ipv6(frame, ip_offset)?,
        _ => return Ok(None),
    };
    let (source_port, destination_port) = packet.ports.unwrap_or((0, 0));
    let direction = direction(packet.source, packet.destination, local_ips);
    Ok(Some(PacketMeta {
        timestamp,
        wire_bytes,
        key: FlowKey {
            capture_point: capture_point.to_owned(),
            direction,
            protocol: packet.protocol.into(),
            source_ip: packet.source,
            destination_ip: packet.destination,
            source_port: packet.ports.map(|_| source_port),
            destination_port: packet.ports.map(|_| destination_port),
        },
    }))
}

fn ip_offset(frame: &[u8], link_type: i32) -> Result<(usize, u16), PacketError> {
    match link_type {
        LINKTYPE_ETHERNET => {
            require(frame, 14, "ethernet")?;
            let mut offset = 14;
            let mut ether_type = u16::from_be_bytes([frame[12], frame[13]]);
            for _ in 0..2 {
                if !matches!(ether_type, 0x8100 | 0x88a8) {
                    break;
                }
                require(frame, offset + 4, "vlan")?;
                ether_type = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
                offset += 4;
            }
            Ok((offset, ether_type))
        }
        LINKTYPE_RAW => {
            require(frame, 1, "raw IP")?;
            match frame[0] >> 4 {
                4 => Ok((0, 0x0800)),
                6 => Ok((0, 0x86dd)),
                _ => Err(PacketError::Invalid("raw IP")),
            }
        }
        LINKTYPE_LINUX_SLL => {
            require(frame, 16, "linux cooked")?;
            Ok((16, u16::from_be_bytes([frame[14], frame[15]])))
        }
        LINKTYPE_LINUX_SLL2 => {
            require(frame, 20, "linux cooked v2")?;
            Ok((20, u16::from_be_bytes([frame[0], frame[1]])))
        }
        other => Err(PacketError::UnsupportedLinkType(other)),
    }
}

fn parse_ipv4(frame: &[u8], offset: usize) -> Result<IpPacket, PacketError> {
    require(frame, offset + 20, "IPv4")?;
    if frame[offset] >> 4 != 4 {
        return Err(PacketError::Invalid("IPv4"));
    }
    let header_len = usize::from(frame[offset] & 0x0f) * 4;
    if header_len < 20 {
        return Err(PacketError::Invalid("IPv4"));
    }
    require(frame, offset + header_len, "IPv4")?;
    let protocol = frame[offset + 9];
    let source_ip = IpAddr::V4(Ipv4Addr::new(
        frame[offset + 12],
        frame[offset + 13],
        frame[offset + 14],
        frame[offset + 15],
    ));
    let destination_ip = IpAddr::V4(Ipv4Addr::new(
        frame[offset + 16],
        frame[offset + 17],
        frame[offset + 18],
        frame[offset + 19],
    ));
    let fragment = u16::from_be_bytes([frame[offset + 6], frame[offset + 7]]);
    let ports = if fragment & 0x1fff == 0 {
        parse_ports(frame, offset + header_len, protocol)?
    } else {
        None
    };
    Ok(IpPacket {
        source: source_ip,
        destination: destination_ip,
        protocol,
        ports,
    })
}

fn parse_ipv6(frame: &[u8], offset: usize) -> Result<IpPacket, PacketError> {
    require(frame, offset + 40, "IPv6")?;
    if frame[offset] >> 4 != 6 {
        return Err(PacketError::Invalid("IPv6"));
    }
    let source: [u8; 16] = frame[offset + 8..offset + 24]
        .try_into()
        .map_err(|_| PacketError::Truncated("IPv6"))?;
    let destination: [u8; 16] = frame[offset + 24..offset + 40]
        .try_into()
        .map_err(|_| PacketError::Truncated("IPv6"))?;
    let mut protocol = frame[offset + 6];
    let mut transport_offset = offset + 40;
    let mut first_fragment = true;
    for _ in 0..8 {
        match protocol {
            0 | 43 | 60 => {
                require(frame, transport_offset + 2, "IPv6 extension")?;
                let next = frame[transport_offset];
                let length = (usize::from(frame[transport_offset + 1]) + 1) * 8;
                require(frame, transport_offset + length, "IPv6 extension")?;
                protocol = next;
                transport_offset += length;
            }
            44 => {
                require(frame, transport_offset + 8, "IPv6 fragment")?;
                let next = frame[transport_offset];
                let fragment =
                    u16::from_be_bytes([frame[transport_offset + 2], frame[transport_offset + 3]]);
                first_fragment = fragment & 0xfff8 == 0;
                protocol = next;
                transport_offset += 8;
            }
            51 => {
                require(frame, transport_offset + 2, "IPv6 AH")?;
                let next = frame[transport_offset];
                let length = (usize::from(frame[transport_offset + 1]) + 2) * 4;
                require(frame, transport_offset + length, "IPv6 AH")?;
                protocol = next;
                transport_offset += length;
            }
            _ => break,
        }
    }
    let ports = if first_fragment {
        parse_ports(frame, transport_offset, protocol)?
    } else {
        None
    };
    Ok(IpPacket {
        source: IpAddr::V6(Ipv6Addr::from(source)),
        destination: IpAddr::V6(Ipv6Addr::from(destination)),
        protocol,
        ports,
    })
}

fn parse_ports(
    frame: &[u8],
    transport_offset: usize,
    protocol: u8,
) -> Result<Option<(u16, u16)>, PacketError> {
    if !matches!(
        TransportProtocol::from(protocol),
        TransportProtocol::Tcp | TransportProtocol::Udp
    ) {
        return Ok(None);
    }
    require(frame, transport_offset + 4, "transport")?;
    Ok(Some((
        u16::from_be_bytes([frame[transport_offset], frame[transport_offset + 1]]),
        u16::from_be_bytes([frame[transport_offset + 2], frame[transport_offset + 3]]),
    )))
}

fn direction(source: IpAddr, destination: IpAddr, local_ips: &[IpAddr]) -> Direction {
    match (
        local_ips.contains(&source),
        local_ips.contains(&destination),
    ) {
        (true, false) => Direction::Egress,
        (false, true) => Direction::Ingress,
        (true, true) => Direction::Internal,
        (false, false) => Direction::Unknown,
    }
}

fn require(frame: &[u8], length: usize, layer: &'static str) -> Result<(), PacketError> {
    if frame.len() < length {
        Err(PacketError::Truncated(layer))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ethernet_ipv4_tcp_and_direction() {
        let mut frame = vec![0_u8; 14 + 20 + 20];
        frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        frame[14] = 0x45;
        frame[14 + 9] = 6;
        frame[14 + 12..14 + 16].copy_from_slice(&[10, 0, 0, 2]);
        frame[14 + 16..14 + 20].copy_from_slice(&[1, 1, 1, 1]);
        frame[34..36].copy_from_slice(&12345_u16.to_be_bytes());
        frame[36..38].copy_from_slice(&443_u16.to_be_bytes());

        let parsed = parse_packet(
            &frame,
            LINKTYPE_ETHERNET,
            100,
            60,
            "physical:eth0",
            &["10.0.0.2".parse().unwrap()],
        )
        .unwrap()
        .unwrap();

        assert_eq!(parsed.key.direction, Direction::Egress);
        assert_eq!(parsed.key.protocol, TransportProtocol::Tcp);
        assert_eq!(parsed.key.source_port, Some(12345));
        assert_eq!(parsed.key.destination_port, Some(443));
    }

    #[test]
    fn parses_raw_ipv6_udp() {
        let mut frame = vec![0_u8; 40 + 8];
        frame[0] = 0x60;
        frame[6] = 17;
        frame[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        frame[24..40]
            .copy_from_slice(&"2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap().octets());
        frame[40..42].copy_from_slice(&5353_u16.to_be_bytes());
        frame[42..44].copy_from_slice(&53_u16.to_be_bytes());

        let parsed = parse_packet(
            &frame,
            LINKTYPE_RAW,
            100,
            48,
            "tunnel:wg0",
            &[IpAddr::V6(Ipv6Addr::LOCALHOST)],
        )
        .unwrap()
        .unwrap();

        assert_eq!(parsed.key.direction, Direction::Egress);
        assert_eq!(parsed.key.protocol, TransportProtocol::Udp);
        assert_eq!(parsed.key.destination_port, Some(53));
    }

    #[test]
    fn ignores_non_ip_ethernet_frames() {
        let mut frame = vec![0_u8; 42];
        frame[12..14].copy_from_slice(&0x0806_u16.to_be_bytes());
        assert_eq!(
            parse_packet(&frame, LINKTYPE_ETHERNET, 1, 42, "eth0", &[]).unwrap(),
            None
        );
    }
}
