use crate::model::{DecodedPacket, TcpFlags};
use aegis_rules::model::{Direction, Protocol};
use bytes::Bytes;
use etherparse::{NetHeaders, PacketHeaders, TransportHeader};
use std::net::IpAddr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DecodeError {
    #[error("failed to parse IP packet: {0}")]
    Parse(String),
    #[error("unsupported IP version or packet structure")]
    Unsupported,
}

/// Decode a raw IP-layer packet (no Ethernet header) into a `DecodedPacket`.
/// `direction` must be determined by the caller (e.g., from NFQUEUE hook point).
pub fn decode_ip_packet(raw: &[u8], direction: Direction) -> Result<DecodedPacket, DecodeError> {
    // PacketHeaders::from_ip_slice is the correct etherparse 0.15 API for raw IP packets.
    let pkt = PacketHeaders::from_ip_slice(raw)
        .map_err(|e| DecodeError::Parse(e.to_string()))?;

    let (src_ip, dst_ip) = match &pkt.net {
        Some(NetHeaders::Ipv4(h, _)) => (
            IpAddr::V4(h.source.into()),
            IpAddr::V4(h.destination.into()),
        ),
        Some(NetHeaders::Ipv6(h, _)) => (
            IpAddr::V6(h.source.into()),
            IpAddr::V6(h.destination.into()),
        ),
        _ => return Err(DecodeError::Unsupported),
    };

    let packet_len = raw.len() as u32;
    // PayloadSlice is an enum in etherparse 0.15; use .slice() to get the underlying bytes.
    let payload_bytes = Bytes::copy_from_slice(pkt.payload.slice());

    match &pkt.transport {
        Some(TransportHeader::Tcp(tcp)) => {
            let flags = TcpFlags {
                syn: tcp.syn,
                ack: tcp.ack,
                fin: tcp.fin,
                rst: tcp.rst,
                psh: tcp.psh,
                urg: tcp.urg,
            };
            Ok(DecodedPacket {
                src_ip,
                dst_ip,
                src_port: Some(tcp.source_port),
                dst_port: Some(tcp.destination_port),
                protocol: Protocol::Tcp,
                direction,
                tcp_flags: Some(flags),
                payload: payload_bytes,
                packet_len,
            })
        }
        Some(TransportHeader::Udp(udp)) => Ok(DecodedPacket {
            src_ip,
            dst_ip,
            src_port: Some(udp.source_port),
            dst_port: Some(udp.destination_port),
            protocol: Protocol::Udp,
            direction,
            tcp_flags: None,
            payload: payload_bytes,
            packet_len,
        }),
        Some(TransportHeader::Icmpv4(_)) | Some(TransportHeader::Icmpv6(_)) => Ok(DecodedPacket {
            src_ip,
            dst_ip,
            src_port: None,
            dst_port: None,
            protocol: Protocol::Icmp,
            direction,
            tcp_flags: None,
            payload: payload_bytes,
            packet_len,
        }),
        None => Err(DecodeError::Unsupported),
    }
}
