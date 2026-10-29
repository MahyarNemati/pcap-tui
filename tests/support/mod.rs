//! Builders for synthetic capture files and packets.
//!
//! Everything here writes bytes by hand from the file-format and protocol
//! specs. That is the point: if the tests used libpcap to produce the
//! fixtures and libpcap to read them back, a shared misunderstanding of the
//! format would cancel out and the tests would pass on a wrong reader.

#![allow(dead_code)]

use std::io::Write;
use std::path::PathBuf;

/// PcapWriter builds a classic libpcap file.
pub struct PcapWriter {
    pub bytes: Vec<u8>,
    big_endian: bool,
    nanos: bool,
}

impl PcapWriter {
    /// A little-endian, microsecond-resolution file, which is what tcpdump
    /// writes on every machine anyone is likely to use.
    pub fn new(link_type: u32) -> Self {
        Self::with_options(link_type, false, false)
    }

    pub fn big_endian(link_type: u32) -> Self {
        Self::with_options(link_type, true, false)
    }

    pub fn nanos(link_type: u32) -> Self {
        Self::with_options(link_type, false, true)
    }

    pub fn with_options(link_type: u32, big_endian: bool, nanos: bool) -> Self {
        let mut w = PcapWriter {
            bytes: Vec::new(),
            big_endian,
            nanos,
        };
        let magic: u32 = if nanos { 0xa1b2_3c4d } else { 0xa1b2_c3d4 };
        w.u32(magic);
        w.u16(2); // version major
        w.u16(4); // version minor
        w.u32(0); // thiszone
        w.u32(0); // sigfigs
        w.u32(262_144); // snaplen
        w.u32(link_type);
        w
    }

    /// push appends a record whose captured and original lengths match.
    pub fn push(&mut self, seconds: u32, subsec: u32, data: &[u8]) -> &mut Self {
        self.push_truncated(seconds, subsec, data, data.len() as u32)
    }

    /// push_truncated appends a record that claims to be longer than the
    /// bytes actually stored, which is what a short snaplen produces.
    pub fn push_truncated(
        &mut self,
        seconds: u32,
        subsec: u32,
        data: &[u8],
        original_len: u32,
    ) -> &mut Self {
        self.u32(seconds);
        self.u32(subsec);
        self.u32(data.len() as u32);
        self.u32(original_len);
        self.bytes.extend_from_slice(data);
        self
    }

    /// raw appends bytes verbatim, for building malformed files.
    pub fn raw(&mut self, data: &[u8]) -> &mut Self {
        self.bytes.extend_from_slice(data);
        self
    }

    pub fn write_to_temp(&self, name: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(name);
        let mut f = std::fs::File::create(&path).expect("create");
        f.write_all(&self.bytes).expect("write");
        (dir, path)
    }

    fn u16(&mut self, v: u16) {
        if self.big_endian {
            self.bytes.extend_from_slice(&v.to_be_bytes());
        } else {
            self.bytes.extend_from_slice(&v.to_le_bytes());
        }
    }

    fn u32(&mut self, v: u32) {
        if self.big_endian {
            self.bytes.extend_from_slice(&v.to_be_bytes());
        } else {
            self.bytes.extend_from_slice(&v.to_le_bytes());
        }
    }

    /// Whether this file stores sub-second values as nanoseconds.
    pub fn is_nanos(&self) -> bool {
        self.nanos
    }
}

/// PcapngWriter builds a pcapng file: a section header, interface
/// descriptions, and packet blocks.
pub struct PcapngWriter {
    pub bytes: Vec<u8>,
    interfaces: Vec<u32>, // tsresol divisor exponents, per interface
}

impl PcapngWriter {
    pub fn new() -> Self {
        let mut w = PcapngWriter {
            bytes: Vec::new(),
            interfaces: Vec::new(),
        };
        // Section Header Block. The length appears twice so a reader can
        // walk the file backwards as well as forwards.
        let body = {
            let mut b = Vec::new();
            b.extend_from_slice(&0x1a2b_3c4du32.to_le_bytes()); // byte-order magic
            b.extend_from_slice(&1u16.to_le_bytes()); // major
            b.extend_from_slice(&0u16.to_le_bytes()); // minor
            b.extend_from_slice(&(-1i64).to_le_bytes()); // section length: unknown
            b
        };
        w.block(0x0a0d_0d0a, &body);
        w
    }

    /// interface appends an Interface Description Block and returns its id.
    pub fn interface(&mut self, link_type: u16, snaplen: u32) -> u32 {
        let mut body = Vec::new();
        body.extend_from_slice(&link_type.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes()); // reserved
        body.extend_from_slice(&snaplen.to_le_bytes());
        self.block(0x0000_0001, &body);
        self.interfaces.push(6); // default tsresol: microseconds
        (self.interfaces.len() - 1) as u32
    }

    /// packet appends an Enhanced Packet Block.
    pub fn packet(&mut self, interface: u32, timestamp_usec: u64, data: &[u8]) -> &mut Self {
        self.packet_truncated(interface, timestamp_usec, data, data.len() as u32)
    }

    pub fn packet_truncated(
        &mut self,
        interface: u32,
        timestamp_usec: u64,
        data: &[u8],
        original_len: u32,
    ) -> &mut Self {
        let mut body = Vec::new();
        body.extend_from_slice(&interface.to_le_bytes());
        // The timestamp is split across two 32-bit words, high first.
        body.extend_from_slice(&((timestamp_usec >> 32) as u32).to_le_bytes());
        body.extend_from_slice(&((timestamp_usec & 0xffff_ffff) as u32).to_le_bytes());
        body.extend_from_slice(&(data.len() as u32).to_le_bytes());
        body.extend_from_slice(&original_len.to_le_bytes());
        body.extend_from_slice(data);
        // Packet data is padded to a 4-byte boundary; the padding is not
        // counted in captured_len, which is a classic place to get the
        // arithmetic wrong.
        while body.len() % 4 != 0 {
            body.push(0);
        }
        self.block(0x0000_0006, &body);
        self
    }

    /// simple_packet appends a Simple Packet Block, which has no timestamp
    /// and no interface id and so must inherit both.
    pub fn simple_packet(&mut self, data: &[u8]) -> &mut Self {
        let mut body = Vec::new();
        body.extend_from_slice(&(data.len() as u32).to_le_bytes());
        body.extend_from_slice(data);
        while body.len() % 4 != 0 {
            body.push(0);
        }
        self.block(0x0000_0003, &body);
        self
    }

    /// unknown_block appends a block type a reader has never heard of. A
    /// conforming reader skips it using the length, rather than failing.
    pub fn unknown_block(&mut self, payload: &[u8]) -> &mut Self {
        self.block(0x0000_0bad, payload);
        self
    }

    fn block(&mut self, block_type: u32, body: &[u8]) {
        let total = 12 + body.len() as u32;
        self.bytes.extend_from_slice(&block_type.to_le_bytes());
        self.bytes.extend_from_slice(&total.to_le_bytes());
        self.bytes.extend_from_slice(body);
        self.bytes.extend_from_slice(&total.to_le_bytes());
    }

    pub fn write_to_temp(&self, name: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(name);
        std::fs::write(&path, &self.bytes).expect("write");
        (dir, path)
    }
}

impl Default for PcapngWriter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------- packets

pub const MAC_A: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x0a];
pub const MAC_B: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x0b];

/// ethernet wraps a payload in an Ethernet II header.
pub fn ethernet(src: [u8; 6], dst: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(14 + payload.len());
    v.extend_from_slice(&dst);
    v.extend_from_slice(&src);
    v.extend_from_slice(&ethertype.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// vlan inserts an 802.1Q tag before the inner ethertype.
pub fn vlan(vid: u16, inner_ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&vid.to_be_bytes());
    v.extend_from_slice(&inner_ethertype.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// Options for an IPv4 header, so a test can state only what it cares about.
pub struct Ipv4 {
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub protocol: u8,
    pub ttl: u8,
    pub ihl_words: u8,
    pub flags_and_offset: u16,
    pub identification: u16,
}

impl Default for Ipv4 {
    fn default() -> Self {
        Ipv4 {
            src: [10, 0, 0, 1],
            dst: [10, 0, 0, 2],
            protocol: 6,
            ttl: 64,
            ihl_words: 5,
            flags_and_offset: 0,
            identification: 0x1234,
        }
    }
}

/// ipv4 builds a header and appends the payload, computing the checksum so
/// the fixture is a packet a real stack would accept.
pub fn ipv4(opts: Ipv4, payload: &[u8]) -> Vec<u8> {
    let header_len = opts.ihl_words as usize * 4;
    let total_len = (header_len + payload.len()) as u16;
    let mut h = vec![0u8; header_len];
    h[0] = 0x40 | (opts.ihl_words & 0x0f);
    h[1] = 0;
    h[2..4].copy_from_slice(&total_len.to_be_bytes());
    h[4..6].copy_from_slice(&opts.identification.to_be_bytes());
    h[6..8].copy_from_slice(&opts.flags_and_offset.to_be_bytes());
    h[8] = opts.ttl;
    h[9] = opts.protocol;
    h[12..16].copy_from_slice(&opts.src);
    h[16..20].copy_from_slice(&opts.dst);
    let sum = checksum(&h);
    h[10..12].copy_from_slice(&sum.to_be_bytes());
    h.extend_from_slice(payload);
    h
}

/// ipv6 builds a fixed 40-byte header. `next_header` is whatever comes
/// next, which may itself be an extension header.
pub fn ipv6(src: [u8; 16], dst: [u8; 16], next_header: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(40 + payload.len());
    v.extend_from_slice(&0x6000_0000u32.to_be_bytes()); // version 6
    v.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    v.push(next_header);
    v.push(64); // hop limit
    v.extend_from_slice(&src);
    v.extend_from_slice(&dst);
    v.extend_from_slice(payload);
    v
}

/// ext_header builds an IPv6 extension header in the standard shape:
/// next-header byte, length in 8-byte units not counting the first 8.
pub fn ext_header(next_header: u8, extra_octets: usize) -> Vec<u8> {
    let total = 8 + extra_octets;
    assert!(
        total.is_multiple_of(8),
        "extension headers are a multiple of 8 bytes"
    );
    let mut v = vec![0u8; total];
    v[0] = next_header;
    v[1] = ((total / 8) - 1) as u8;
    v
}

pub struct Tcp {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub data_offset_words: u8,
}

impl Default for Tcp {
    fn default() -> Self {
        Tcp {
            src_port: 50000,
            dst_port: 80,
            seq: 1,
            ack: 0,
            flags: 0x02, // SYN
            window: 65535,
            data_offset_words: 5,
        }
    }
}

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;

pub fn tcp(opts: Tcp, payload: &[u8]) -> Vec<u8> {
    let header_len = opts.data_offset_words as usize * 4;
    let mut h = vec![0u8; header_len];
    h[0..2].copy_from_slice(&opts.src_port.to_be_bytes());
    h[2..4].copy_from_slice(&opts.dst_port.to_be_bytes());
    h[4..8].copy_from_slice(&opts.seq.to_be_bytes());
    h[8..12].copy_from_slice(&opts.ack.to_be_bytes());
    h[12] = opts.data_offset_words << 4;
    h[13] = opts.flags;
    h[14..16].copy_from_slice(&opts.window.to_be_bytes());
    h.extend_from_slice(payload);
    h
}

pub fn udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + payload.len());
    v.extend_from_slice(&src_port.to_be_bytes());
    v.extend_from_slice(&dst_port.to_be_bytes());
    v.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    v.extend_from_slice(&0u16.to_be_bytes()); // checksum: optional on IPv4
    v.extend_from_slice(payload);
    v
}

pub fn icmp_echo_request(id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![8, 0, 0, 0];
    v.extend_from_slice(&id.to_be_bytes());
    v.extend_from_slice(&seq.to_be_bytes());
    v.extend_from_slice(payload);
    let sum = checksum(&v);
    v[2..4].copy_from_slice(&sum.to_be_bytes());
    v
}

/// dns_query builds a query for a name, encoded as length-prefixed labels.
pub fn dns_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&id.to_be_bytes());
    v.extend_from_slice(&0x0100u16.to_be_bytes()); // standard query, recursion desired
    v.extend_from_slice(&1u16.to_be_bytes()); // one question
    v.extend_from_slice(&0u16.to_be_bytes()); // answers
    v.extend_from_slice(&0u16.to_be_bytes()); // authority
    v.extend_from_slice(&0u16.to_be_bytes()); // additional
    for label in name.split('.').filter(|l| !l.is_empty()) {
        v.push(label.len() as u8);
        v.extend_from_slice(label.as_bytes());
    }
    v.push(0); // root label
    v.extend_from_slice(&qtype.to_be_bytes());
    v.extend_from_slice(&1u16.to_be_bytes()); // class IN
    v
}

/// tls_client_hello builds enough of a TLS record for identification: the
/// record header, the handshake type, and an SNI extension.
pub fn tls_client_hello(server_name: &str) -> Vec<u8> {
    let mut hello = Vec::new();
    hello.extend_from_slice(&0x0303u16.to_be_bytes()); // client version TLS 1.2
    hello.extend_from_slice(&[0u8; 32]); // random
    hello.push(0); // no session id
    hello.extend_from_slice(&2u16.to_be_bytes()); // cipher suites length
    hello.extend_from_slice(&0x1301u16.to_be_bytes());
    hello.push(1); // compression methods length
    hello.push(0);

    let mut sni = Vec::new();
    sni.extend_from_slice(&((server_name.len() + 3) as u16).to_be_bytes());
    sni.push(0); // host_name
    sni.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
    sni.extend_from_slice(server_name.as_bytes());

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&0u16.to_be_bytes()); // extension type: server_name
    extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni);

    hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    hello.extend_from_slice(&extensions);

    let mut handshake = vec![0x01]; // client_hello
    handshake.extend_from_slice(&(hello.len() as u32).to_be_bytes()[1..]); // 24-bit length
    handshake.extend_from_slice(&hello);

    let mut record = vec![0x16, 0x03, 0x01]; // handshake, TLS 1.0 record version
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

pub fn arp_request(sender_mac: [u8; 6], sender_ip: [u8; 4], target_ip: [u8; 4]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&1u16.to_be_bytes()); // Ethernet
    v.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4
    v.push(6); // hardware length
    v.push(4); // protocol length
    v.extend_from_slice(&1u16.to_be_bytes()); // request
    v.extend_from_slice(&sender_mac);
    v.extend_from_slice(&sender_ip);
    v.extend_from_slice(&[0u8; 6]); // target mac: unknown
    v.extend_from_slice(&target_ip);
    v
}

/// checksum is the internet checksum from RFC 1071.
pub fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < bytes.len() {
        sum += u16::from_be_bytes([bytes[i], bytes[i + 1]]) as u32;
        i += 2;
    }
    if i < bytes.len() {
        sum += (bytes[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// A small but varied capture: TCP, UDP/DNS, TLS, ICMP and ARP over
/// Ethernet. Several tests want the same mixture.
pub fn mixed_capture() -> PcapWriter {
    let mut w = PcapWriter::new(1);
    let syn = ethernet(
        MAC_A,
        MAC_B,
        0x0800,
        &ipv4(
            Ipv4 {
                protocol: 6,
                ..Default::default()
            },
            &tcp(
                Tcp {
                    flags: TCP_SYN,
                    ..Default::default()
                },
                &[],
            ),
        ),
    );
    w.push(1_700_000_000, 100_000, &syn);

    let synack = ethernet(
        MAC_B,
        MAC_A,
        0x0800,
        &ipv4(
            Ipv4 {
                src: [10, 0, 0, 2],
                dst: [10, 0, 0, 1],
                protocol: 6,
                ..Default::default()
            },
            &tcp(
                Tcp {
                    src_port: 80,
                    dst_port: 50000,
                    flags: TCP_SYN | TCP_ACK,
                    ack: 2,
                    ..Default::default()
                },
                &[],
            ),
        ),
    );
    w.push(1_700_000_000, 200_000, &synack);

    let dns = ethernet(
        MAC_A,
        MAC_B,
        0x0800,
        &ipv4(
            Ipv4 {
                protocol: 17,
                dst: [10, 0, 0, 53],
                ..Default::default()
            },
            &udp(54321, 53, &dns_query(0xbeef, "example.com", 1)),
        ),
    );
    w.push(1_700_000_001, 0, &dns);

    let tls = ethernet(
        MAC_A,
        MAC_B,
        0x0800,
        &ipv4(
            Ipv4 {
                protocol: 6,
                dst: [93, 184, 216, 34],
                ..Default::default()
            },
            &tcp(
                Tcp {
                    src_port: 50001,
                    dst_port: 443,
                    flags: TCP_PSH | TCP_ACK,
                    ..Default::default()
                },
                &tls_client_hello("example.com"),
            ),
        ),
    );
    w.push(1_700_000_002, 500_000, &tls);

    let ping = ethernet(
        MAC_A,
        MAC_B,
        0x0800,
        &ipv4(
            Ipv4 {
                protocol: 1,
                dst: [8, 8, 8, 8],
                ..Default::default()
            },
            &icmp_echo_request(1, 1, b"abcdefgh"),
        ),
    );
    w.push(1_700_000_003, 0, &ping);

    let arp = ethernet(
        MAC_A,
        [0xff; 6],
        0x0806,
        &arp_request(MAC_A, [10, 0, 0, 1], [10, 0, 0, 254]),
    );
    w.push(1_700_000_004, 0, &arp);

    w
}
