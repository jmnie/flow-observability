use std::collections::BTreeMap;

use crate::{model::FlowBucket, packet::PacketMeta};

#[derive(Debug)]
pub struct Aggregator {
    bucket_seconds: u64,
    flows: BTreeMap<(u64, crate::model::FlowKey), (u64, u64)>,
}

impl Aggregator {
    pub fn new(bucket_seconds: u64) -> Self {
        assert!(bucket_seconds > 0);
        Self {
            bucket_seconds,
            flows: BTreeMap::new(),
        }
    }

    pub fn push(&mut self, packet: PacketMeta) {
        let bucket_start = packet.timestamp / self.bucket_seconds * self.bucket_seconds;
        let counters = self.flows.entry((bucket_start, packet.key)).or_default();
        counters.0 += 1;
        counters.1 += packet.wire_bytes;
    }

    pub fn drain_before(&mut self, bucket_start: u64) -> Vec<FlowBucket> {
        let retained = self.flows.split_off(&(bucket_start, minimum_flow_key()));
        let drained = std::mem::replace(&mut self.flows, retained);
        to_buckets(drained)
    }

    pub fn drain_all(&mut self) -> Vec<FlowBucket> {
        to_buckets(std::mem::take(&mut self.flows))
    }
}

fn to_buckets(flows: BTreeMap<(u64, crate::model::FlowKey), (u64, u64)>) -> Vec<FlowBucket> {
    flows
        .into_iter()
        .map(|((bucket_start, key), (packets, bytes))| FlowBucket {
            bucket_start,
            key,
            packets,
            bytes,
        })
        .collect()
}

fn minimum_flow_key() -> crate::model::FlowKey {
    crate::model::FlowKey {
        capture_point: String::new(),
        direction: crate::model::Direction::Ingress,
        protocol: crate::model::TransportProtocol::Tcp,
        source_ip: "0.0.0.0".parse().expect("valid minimum IP"),
        destination_ip: "0.0.0.0".parse().expect("valid minimum IP"),
        source_port: None,
        destination_port: None,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::model::{Direction, FlowKey, TransportProtocol};

    fn packet(timestamp: u64, bytes: u64) -> PacketMeta {
        PacketMeta {
            timestamp,
            wire_bytes: bytes,
            key: FlowKey {
                capture_point: "physical:eth0".into(),
                direction: Direction::Egress,
                protocol: TransportProtocol::Tcp,
                source_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                destination_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                source_port: Some(12345),
                destination_port: Some(443),
            },
        }
    }

    #[test]
    fn aggregates_by_ten_second_bucket() {
        let mut aggregator = Aggregator::new(10);
        aggregator.push(packet(11, 100));
        aggregator.push(packet(19, 60));
        aggregator.push(packet(20, 40));

        let first = aggregator.drain_before(20);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].bucket_start, 10);
        assert_eq!((first[0].packets, first[0].bytes), (2, 160));
        assert_eq!(aggregator.drain_all()[0].bucket_start, 20);
    }
}
