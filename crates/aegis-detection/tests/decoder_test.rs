use aegis_detection::decoder::decode_ip_packet;
use aegis_rules::model::{Direction, Protocol};

/// Build a minimal IPv4+TCP SYN packet in raw bytes.
/// Structure: IPv4 header (20 bytes) + TCP header (20 bytes), no payload.
fn make_tcp_syn_packet(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut buf = vec![0u8; 40];
    // IPv4 header
    buf[0] = 0x45; // version=4, IHL=5
    buf[1] = 0x00; // DSCP/ECN
    buf[2] = 0x00;
    buf[3] = 0x28; // total length = 40
    buf[4] = 0x00;
    buf[5] = 0x01; // identification
    buf[6] = 0x40;
    buf[7] = 0x00; // flags (DF), fragment offset=0
    buf[8] = 0x40; // TTL=64
    buf[9] = 0x06; // protocol = TCP
                   // checksum bytes 10-11 left as 0 (etherparse doesn't validate)
    buf[12..16].copy_from_slice(&src);
    buf[16..20].copy_from_slice(&dst);
    // TCP header
    buf[20] = (src_port >> 8) as u8;
    buf[21] = (src_port & 0xff) as u8;
    buf[22] = (dst_port >> 8) as u8;
    buf[23] = (dst_port & 0xff) as u8;
    // seq, ack = 0
    buf[32] = 0x50; // data offset = 5 (20 bytes), reserved=0
    buf[33] = 0x02; // SYN flag
    buf[34] = 0xff;
    buf[35] = 0xff; // window size
                    // checksum, urgent = 0
    buf
}

/// Build a minimal IPv4+UDP packet.
fn make_udp_packet(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut buf = vec![0u8; 28];
    buf[0] = 0x45;
    buf[1] = 0x00;
    buf[2] = 0x00;
    buf[3] = 0x1c; // total length = 28
    buf[4] = 0x00;
    buf[5] = 0x02;
    buf[6] = 0x40;
    buf[7] = 0x00;
    buf[8] = 0x40;
    buf[9] = 0x11; // protocol = UDP
    buf[12..16].copy_from_slice(&src);
    buf[16..20].copy_from_slice(&dst);
    // UDP header
    buf[20] = (src_port >> 8) as u8;
    buf[21] = (src_port & 0xff) as u8;
    buf[22] = (dst_port >> 8) as u8;
    buf[23] = (dst_port & 0xff) as u8;
    buf[24] = 0x00;
    buf[25] = 0x08; // length = 8 (header only)
    buf
}

#[test]
fn decode_tcp_syn_extracts_ips_and_ports() {
    let raw = make_tcp_syn_packet([1, 2, 3, 4], [5, 6, 7, 8], 12345, 80);
    let pkt = decode_ip_packet(&raw, Direction::Inbound).unwrap();
    assert_eq!(pkt.src_ip.to_string(), "1.2.3.4");
    assert_eq!(pkt.dst_ip.to_string(), "5.6.7.8");
    assert_eq!(pkt.src_port, Some(12345));
    assert_eq!(pkt.dst_port, Some(80));
    assert!(matches!(pkt.protocol, Protocol::Tcp));
}

#[test]
fn decode_tcp_syn_flag_set() {
    let raw = make_tcp_syn_packet([1, 2, 3, 4], [5, 6, 7, 8], 1024, 443);
    let pkt = decode_ip_packet(&raw, Direction::Inbound).unwrap();
    let flags = pkt.tcp_flags.expect("TCP packet must have flags");
    assert!(flags.syn);
    assert!(!flags.ack);
    assert!(!flags.rst);
    assert!(!flags.fin);
}

#[test]
fn decode_udp_extracts_ports() {
    let raw = make_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 5000, 53);
    let pkt = decode_ip_packet(&raw, Direction::Outbound).unwrap();
    assert_eq!(pkt.src_port, Some(5000));
    assert_eq!(pkt.dst_port, Some(53));
    assert!(matches!(pkt.protocol, Protocol::Udp));
    assert!(pkt.tcp_flags.is_none());
}

#[test]
fn decode_invalid_bytes_returns_error() {
    let bad = vec![0xffu8; 4];
    assert!(decode_ip_packet(&bad, Direction::Inbound).is_err());
}

#[test]
fn decode_direction_preserved() {
    let raw = make_tcp_syn_packet([1, 2, 3, 4], [5, 6, 7, 8], 100, 200);
    let pkt = decode_ip_packet(&raw, Direction::Outbound).unwrap();
    assert!(matches!(
        pkt.direction,
        aegis_rules::model::Direction::Outbound
    ));
}
