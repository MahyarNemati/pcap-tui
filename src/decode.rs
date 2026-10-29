//! Protocol decoders.
//!
//! Every decoder here follows one rule: **never index without checking the
//! length first**. A capture file is attacker-controlled input, and a packet
//! can be truncated by the capture snaplen even when nobody is being hostile.
//! A decoder that assumes a header is complete panics on perfectly ordinary
//! traffic.
//!
//! So each function returns an `Option` and the caller degrades gracefully:
//! an undecodable layer is shown as such rather than crashing the viewer.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::pcap::{LinkType, Packet};

/// A MAC address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacAddr(pub [u8; 6]);

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

/// Transport-layer protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Other(u8),
}

impl Protocol {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Protocol::Icmp,
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            58 => Protocol::Icmpv6,
            other => Protocol::Other(other),
        }
    }

    pub fn name(self) -> String {
        match self {
            Protocol::Tcp => "TCP".into(),
            Protocol::Udp => "UDP".into(),
            Protocol::Icmp => "ICMP".into(),
            Protocol::Icmpv6 => "ICMPv6".into(),
            Protocol::Other(v) => format!("IP/{v}"),
        }
    }
}

/// TCP flags, which are what make a TCP stream readable at a glance.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
}

impl TcpFlags {
    fn from_bits(bits: u8) -> Self {
        TcpFlags {
            fin: bits & 0x01 != 0,
            syn: bits & 0x02 != 0,
            rst: bits & 0x04 != 0,
            psh: bits & 0x08 != 0,
            ack: bits & 0x10 != 0,
            urg: bits & 0x20 != 0,
            ece: bits & 0x40 != 0,
            cwr: bits & 0x80 != 0,
        }
    }
}

impl fmt::Display for TcpFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // tcpdump's compact form, which is worth copying exactly: ACK is a
        // period rather than a letter, so the flags that change the state of
        // a connection stand out from the acknowledgements that do not.
        // Order is FIN, SYN, RST, PSH, ACK, URG, ECE, CWR.
        let mut s = String::new();
        for (set, ch) in [
            (self.fin, 'F'),
            (self.syn, 'S'),
            (self.rst, 'R'),
            (self.psh, 'P'),
            (self.ack, '.'),
            (self.urg, 'U'),
            (self.ece, 'E'),
            (self.cwr, 'W'),
        ] {
            if set {
                s.push(ch);
            }
        }
        if s.is_empty() {
            s.push_str("none");
        }
        f.write_str(&s)
    }
}

/// A fully decoded packet, as far as decoding succeeded.
#[derive(Debug, Clone, Default)]
pub struct Decoded {
    pub src_mac: Option<MacAddr>,
    pub dst_mac: Option<MacAddr>,
    pub ethertype: Option<u16>,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub ttl: Option<u8>,
    pub protocol: Option<Protocol>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub tcp_flags: Option<TcpFlags>,
    pub seq: Option<u32>,
    pub ack: Option<u32>,
    pub window: Option<u16>,
    /// IP fragmentation state. Fragments are the reason a decoder cannot
    /// assume the transport header is present at all.
    pub fragmented: bool,
    pub fragment_offset: u16,
    /// Payload after the transport header.
    pub payload_offset: usize,
    pub payload_len: usize,
    /// A one-line summary of the application layer, when recognisable.
    pub info: String,
    /// The highest protocol identified, for the protocol column.
    pub top_protocol: String,
}

impl Decoded {
    /// A "src:port → dst:port" style endpoint pair.
    pub fn flow(&self) -> String {
        let fmt_end = |ip: &Option<IpAddr>, port: &Option<u16>| -> String {
            match (ip, port) {
                (Some(ip), Some(p)) => {
                    // IPv6 needs brackets to disambiguate the port colon.
                    if ip.is_ipv6() {
                        format!("[{ip}]:{p}")
                    } else {
                        format!("{ip}:{p}")
                    }
                }
                (Some(ip), None) => ip.to_string(),
                _ => "?".into(),
            }
        };
        format!(
            "{} → {}",
            fmt_end(&self.src_ip, &self.src_port),
            fmt_end(&self.dst_ip, &self.dst_port)
        )
    }
}

/// Decodes a packet as far as it can.
///
/// Always returns a Decoded: a packet that cannot be parsed past the link
/// layer still has a length and a timestamp worth showing.
pub fn decode(packet: &Packet) -> Decoded {
    let mut d = Decoded {
        top_protocol: packet.link_type.name(),
        ..Default::default()
    };

    let bytes = &packet.data;

    let network = match packet.link_type {
        LinkType::Ethernet => {
            if bytes.len() < 14 {
                d.info = format!("truncated Ethernet header ({} bytes)", bytes.len());
                return d;
            }
            d.dst_mac = Some(MacAddr([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
            ]));
            d.src_mac = Some(MacAddr([
                bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11],
            ]));
            let mut ethertype = u16::from_be_bytes([bytes[12], bytes[13]]);
            let mut offset = 14usize;

            // A VLAN tag inserts 4 bytes and moves the real ethertype. Up to
            // two tags (QinQ) are handled; a decoder that ignores this reports
            // every tagged packet as protocol 0x8100.
            let mut tags = 0;
            while (ethertype == 0x8100 || ethertype == 0x88a8) && tags < 2 {
                if bytes.len() < offset + 4 {
                    d.info = "truncated VLAN tag".into();
                    return d;
                }
                ethertype = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]);
                offset += 4;
                tags += 1;
            }

            d.ethertype = Some(ethertype);
            match ethertype {
                0x0800 | 0x86dd => &bytes[offset..],
                0x0806 => {
                    d.top_protocol = "ARP".into();
                    d.info = decode_arp(&mut d, &bytes[offset..]);
                    return d;
                }
                other => {
                    d.top_protocol = format!("0x{other:04x}");
                    d.info = format!("unhandled ethertype 0x{other:04x}");
                    return d;
                }
            }
        }
        _ => packet.network_bytes(),
    };

    if network.is_empty() {
        d.info = "no network-layer data".into();
        return d;
    }

    let version = network[0] >> 4;
    let transport = match version {
        4 => match decode_ipv4(network, &mut d) {
            Some(rest) => rest,
            None => return d,
        },
        6 => match decode_ipv6(network, &mut d) {
            Some(rest) => rest,
            None => return d,
        },
        other => {
            d.info = format!("unknown IP version {other}");
            return d;
        }
    };

    // A non-first fragment has no transport header: the ports and flags
    // belong to the first fragment only. Decoding it anyway would print
    // convincing nonsense.
    if d.fragmented && d.fragment_offset > 0 {
        d.top_protocol = format!(
            "{} fragment",
            d.protocol.map(|p| p.name()).unwrap_or_default()
        );
        d.info = format!("IP fragment, offset {}", d.fragment_offset * 8);
        return d;
    }

    match d.protocol {
        Some(Protocol::Tcp) => decode_tcp(transport, &mut d),
        Some(Protocol::Udp) => decode_udp(transport, &mut d),
        Some(Protocol::Icmp) => decode_icmp(transport, &mut d),
        Some(Protocol::Icmpv6) => decode_icmpv6(transport, &mut d),
        _ => {
            d.payload_len = transport.len();
        }
    }
    d
}

fn decode_ipv4<'a>(bytes: &'a [u8], d: &mut Decoded) -> Option<&'a [u8]> {
    if bytes.len() < 20 {
        d.info = format!("truncated IPv4 header ({} bytes)", bytes.len());
        return None;
    }
    // IHL is in 32-bit words and can exceed 5 when options are present, so a
    // fixed 20-byte assumption misparses any packet carrying options.
    let ihl = ((bytes[0] & 0x0f) as usize) * 4;
    if ihl < 20 || bytes.len() < ihl {
        d.info = format!("invalid IPv4 header length {ihl}");
        return None;
    }

    d.ttl = Some(bytes[8]);
    d.protocol = Some(Protocol::from_u8(bytes[9]));
    d.src_ip = Some(IpAddr::V4(Ipv4Addr::new(
        bytes[12], bytes[13], bytes[14], bytes[15],
    )));
    d.dst_ip = Some(IpAddr::V4(Ipv4Addr::new(
        bytes[16], bytes[17], bytes[18], bytes[19],
    )));

    let flags_frag = u16::from_be_bytes([bytes[6], bytes[7]]);
    let more_fragments = flags_frag & 0x2000 != 0;
    d.fragment_offset = flags_frag & 0x1fff;
    d.fragmented = more_fragments || d.fragment_offset > 0;

    d.top_protocol = d
        .protocol
        .map(|p| p.name())
        .unwrap_or_else(|| "IPv4".into());

    // The IP total length is authoritative: trailing bytes beyond it are
    // Ethernet padding, and including them would overstate the payload.
    let total_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    let end = if total_len >= ihl && total_len <= bytes.len() {
        total_len
    } else {
        bytes.len()
    };
    Some(&bytes[ihl..end])
}

fn decode_ipv6<'a>(bytes: &'a [u8], d: &mut Decoded) -> Option<&'a [u8]> {
    if bytes.len() < 40 {
        d.info = format!("truncated IPv6 header ({} bytes)", bytes.len());
        return None;
    }
    d.ttl = Some(bytes[7]); // hop limit
    let mut next_header = bytes[6];

    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&bytes[8..24]);
    dst.copy_from_slice(&bytes[24..40]);
    d.src_ip = Some(IpAddr::V6(Ipv6Addr::from(src)));
    d.dst_ip = Some(IpAddr::V6(Ipv6Addr::from(dst)));

    let payload_len = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
    let end = (40 + payload_len).min(bytes.len());
    let mut rest = &bytes[40..end];

    // IPv6 chains extension headers before the transport header. Walking them
    // is required: a packet with a Hop-by-Hop header would otherwise be
    // decoded as protocol 0, and anything with a Fragment header would be
    // misread entirely.
    let mut hops = 0;
    loop {
        match next_header {
            // Hop-by-Hop, Routing, Destination Options, Mobility: all use the
            // same "next header, length in 8-octet units minus one" shape.
            0 | 43 | 60 | 135 => {
                if rest.len() < 8 || hops > 8 {
                    d.info = "truncated or deeply nested IPv6 extension headers".into();
                    return None;
                }
                let ext_len = (rest[1] as usize + 1) * 8;
                if rest.len() < ext_len {
                    d.info = "truncated IPv6 extension header".into();
                    return None;
                }
                next_header = rest[0];
                rest = &rest[ext_len..];
                hops += 1;
            }
            44 => {
                // Fragment header: fixed 8 bytes, and it tells us the packet
                // is a fragment.
                if rest.len() < 8 {
                    d.info = "truncated IPv6 fragment header".into();
                    return None;
                }
                let offset_flags = u16::from_be_bytes([rest[2], rest[3]]);
                d.fragment_offset = offset_flags >> 3;
                d.fragmented = true;
                next_header = rest[0];
                rest = &rest[8..];
                hops += 1;
            }
            59 => {
                // No next header.
                d.protocol = Some(Protocol::Other(59));
                d.top_protocol = "IPv6 no-next".into();
                return Some(rest);
            }
            _ => break,
        }
    }

    d.protocol = Some(Protocol::from_u8(next_header));
    d.top_protocol = d
        .protocol
        .map(|p| p.name())
        .unwrap_or_else(|| "IPv6".into());
    Some(rest)
}

fn decode_tcp(bytes: &[u8], d: &mut Decoded) {
    if bytes.len() < 20 {
        d.info = format!("truncated TCP header ({} bytes)", bytes.len());
        return;
    }
    d.src_port = Some(u16::from_be_bytes([bytes[0], bytes[1]]));
    d.dst_port = Some(u16::from_be_bytes([bytes[2], bytes[3]]));
    d.seq = Some(u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]));
    d.ack = Some(u32::from_be_bytes([
        bytes[8], bytes[9], bytes[10], bytes[11],
    ]));

    // The data offset is in 32-bit words and is 5 only when there are no
    // options -- which, with timestamps and SACK in use, is almost never.
    let data_offset = ((bytes[12] >> 4) as usize) * 4;
    let flags = TcpFlags::from_bits(bytes[13]);
    d.tcp_flags = Some(flags);
    d.window = Some(u16::from_be_bytes([bytes[14], bytes[15]]));

    let payload = if data_offset >= 20 && bytes.len() >= data_offset {
        &bytes[data_offset..]
    } else {
        &[]
    };
    d.payload_len = payload.len();

    let (src, dst) = (d.src_port.unwrap_or(0), d.dst_port.unwrap_or(0));
    d.info = format!(
        "[{}] seq={} win={} len={}",
        flags,
        d.seq.unwrap_or(0),
        d.window.unwrap_or(0),
        payload.len()
    );

    // Identify the application layer by well-known port, then by content.
    // Port-based identification is a heuristic and labelled as such, because
    // nothing stops a service running elsewhere.
    if let Some(app) = decode_application(src, dst, payload) {
        d.top_protocol = app.0;
        d.info = app.1;
    }
}

fn decode_udp(bytes: &[u8], d: &mut Decoded) {
    if bytes.len() < 8 {
        d.info = format!("truncated UDP header ({} bytes)", bytes.len());
        return;
    }
    d.src_port = Some(u16::from_be_bytes([bytes[0], bytes[1]]));
    d.dst_port = Some(u16::from_be_bytes([bytes[2], bytes[3]]));
    let declared = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;

    // The UDP length includes the 8-byte header.
    let end = if declared >= 8 && declared <= bytes.len() {
        declared
    } else {
        bytes.len()
    };
    let payload = &bytes[8..end];
    d.payload_len = payload.len();
    d.info = format!("len={}", payload.len());

    let (src, dst) = (d.src_port.unwrap_or(0), d.dst_port.unwrap_or(0));
    if src == 53 || dst == 53 || src == 5353 || dst == 5353 {
        d.top_protocol = if src == 5353 || dst == 5353 {
            "MDNS".into()
        } else {
            "DNS".into()
        };
        d.info = decode_dns(payload);
    } else if let Some(app) = decode_application(src, dst, payload) {
        d.top_protocol = app.0;
        d.info = app.1;
    }
}

fn decode_icmp(bytes: &[u8], d: &mut Decoded) {
    if bytes.len() < 4 {
        d.info = "truncated ICMP header".into();
        return;
    }
    d.payload_len = bytes.len().saturating_sub(8);
    let (t, code) = (bytes[0], bytes[1]);
    d.info = match t {
        0 => "echo reply".into(),
        3 => format!(
            "destination unreachable ({})",
            match code {
                0 => "network",
                1 => "host",
                3 => "port",
                4 => "fragmentation needed",
                _ => "other",
            }
        ),
        8 => "echo request".into(),
        11 => "time exceeded".into(),
        other => format!("type {other} code {code}"),
    };
    // The identifier and sequence make a ping trace readable.
    if (t == 0 || t == 8) && bytes.len() >= 8 {
        let id = u16::from_be_bytes([bytes[4], bytes[5]]);
        let seq = u16::from_be_bytes([bytes[6], bytes[7]]);
        d.info = format!("{} id={id} seq={seq}", d.info);
    }
}

fn decode_icmpv6(bytes: &[u8], d: &mut Decoded) {
    if bytes.len() < 4 {
        d.info = "truncated ICMPv6 header".into();
        return;
    }
    d.payload_len = bytes.len().saturating_sub(8);
    d.info = match bytes[0] {
        1 => "destination unreachable".into(),
        2 => "packet too big".into(),
        3 => "time exceeded".into(),
        128 => "echo request".into(),
        129 => "echo reply".into(),
        133 => "router solicitation".into(),
        134 => "router advertisement".into(),
        135 => "neighbour solicitation".into(),
        136 => "neighbour advertisement".into(),
        other => format!("type {other}"),
    };
}

fn decode_arp(d: &mut Decoded, bytes: &[u8]) -> String {
    if bytes.len() < 28 {
        return "truncated ARP".into();
    }
    let op = u16::from_be_bytes([bytes[6], bytes[7]]);
    let sender = Ipv4Addr::new(bytes[14], bytes[15], bytes[16], bytes[17]);
    let target = Ipv4Addr::new(bytes[24], bytes[25], bytes[26], bytes[27]);
    // ARP carries protocol addresses even though it has no IP header. Filling
    // them in means ARP has a flow like everything else, so it groups into
    // the conversation list and answers `ip:10.0.0.1` rather than showing as
    // an anonymous "? → ?" row.
    d.src_ip = Some(IpAddr::V4(sender));
    d.dst_ip = Some(IpAddr::V4(target));
    match op {
        1 => format!("who has {target}? tell {sender}"),
        2 => format!(
            "{sender} is at {}",
            MacAddr([bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13],])
        ),
        other => format!("ARP opcode {other}"),
    }
}

/// decode_dns summarises a DNS message.
fn decode_dns(bytes: &[u8]) -> String {
    if bytes.len() < 12 {
        return "truncated DNS".into();
    }
    let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
    let is_response = flags & 0x8000 != 0;
    let rcode = flags & 0x000f;
    let qdcount = u16::from_be_bytes([bytes[4], bytes[5]]);
    let ancount = u16::from_be_bytes([bytes[6], bytes[7]]);

    let name = read_dns_name(bytes, 12).unwrap_or_else(|| "<unparseable>".into());

    if is_response {
        let status = match rcode {
            0 => String::new(),
            2 => " SERVFAIL".into(),
            3 => " NXDOMAIN".into(),
            5 => " REFUSED".into(),
            other => format!(" rcode={other}"),
        };
        format!("response{status} {name} ({ancount} answer(s))")
    } else {
        format!("query {name} ({qdcount} question(s))")
    }
}

/// read_dns_name decodes a QNAME.
///
/// Compression pointers are deliberately *not* followed. A malicious or
/// corrupt message can contain a pointer loop, and following pointers without
/// a visited set is an infinite loop in a packet viewer -- a denial of service
/// triggered by opening a file.
fn read_dns_name(bytes: &[u8], mut offset: usize) -> Option<String> {
    let mut labels = Vec::new();
    let mut guard = 0;
    while offset < bytes.len() && guard < 64 {
        let len = bytes[offset] as usize;
        if len == 0 {
            break;
        }
        // 0xc0 marks a compression pointer.
        if len & 0xc0 == 0xc0 {
            labels.push("...".to_string());
            break;
        }
        offset += 1;
        if offset + len > bytes.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&bytes[offset..offset + len]).to_string());
        offset += len;
        guard += 1;
    }
    if labels.is_empty() {
        return Some(".".into());
    }
    Some(labels.join("."))
}

/// decode_application identifies the application layer.
///
/// Returns (protocol label, summary). Port numbers are a heuristic -- nothing
/// stops a service running elsewhere -- so content is checked where it is
/// cheap and decisive.
fn decode_application(src: u16, dst: u16, payload: &[u8]) -> Option<(String, String)> {
    if payload.is_empty() {
        return None;
    }

    // TLS: a record starts with content type 0x16 (handshake) and a plausible
    // version. Checking the bytes rather than trusting port 443 catches TLS
    // on any port, which is the common case for anything modern.
    if payload.len() >= 5 && payload[0] == 0x16 && payload[1] == 0x03 {
        let version = match payload[2] {
            1 => "1.0",
            2 => "1.1",
            3 => "1.2+",
            _ => "?",
        };
        let kind = if payload.len() >= 6 && payload[5] == 0x01 {
            "ClientHello"
        } else if payload.len() >= 6 && payload[5] == 0x02 {
            "ServerHello"
        } else {
            "handshake"
        };
        // The SNI is the only plaintext hostname left in a modern TLS
        // connection, which makes it by far the most useful thing in the
        // packet when you are reading a capture.
        if let Some(name) = tls_server_name(payload) {
            return Some((
                "TLS".into(),
                format!("{kind} {name} (record version {version})"),
            ));
        }
        return Some(("TLS".into(), format!("{kind} (record version {version})")));
    }
    if payload.len() >= 3 && payload[0] == 0x17 && payload[1] == 0x03 {
        return Some(("TLS".into(), "application data".into()));
    }

    // HTTP: a request line or a status line.
    if let Some(summary) = decode_http(payload) {
        return Some(("HTTP".into(), summary));
    }

    // Fall back to well-known ports, labelled so the guess is visible.
    let port = well_known(src).or_else(|| well_known(dst))?;
    Some((port.to_string(), format!("{port} (by port)")))
}

/// tls_server_name pulls the SNI host out of a ClientHello.
///
/// Every length in here comes off the wire, so each one is checked against
/// what is actually present before it is used as an index. The walk is a
/// fixed sequence of variable-length fields; reaching the end of the buffer
/// at any point simply means there is no name to report.
fn tls_server_name(payload: &[u8]) -> Option<String> {
    // Record header (5) + handshake type (1) + handshake length (3).
    let hs = payload.get(5..)?;
    if *hs.first()? != 0x01 {
        return None; // only a ClientHello carries an SNI
    }
    let mut p = 4usize; // past handshake type and 24-bit length
    p += 2; // client version
    p += 32; // random
    let session_id_len = *hs.get(p)? as usize;
    p += 1 + session_id_len;
    let cipher_len = be16(hs, p)? as usize;
    p += 2 + cipher_len;
    let compression_len = *hs.get(p)? as usize;
    p += 1 + compression_len;

    let extensions_len = be16(hs, p)? as usize;
    p += 2;
    let extensions = hs.get(p..p + extensions_len)?;

    let mut e = 0usize;
    while e + 4 <= extensions.len() {
        let ext_type = be16(extensions, e)?;
        let ext_len = be16(extensions, e + 2)? as usize;
        let body = extensions.get(e + 4..e + 4 + ext_len)?;
        if ext_type == 0x0000 {
            // server_name: a list of names, each a type byte and a length.
            let list_len = be16(body, 0)? as usize;
            let list = body.get(2..2 + list_len)?;
            let mut i = 0usize;
            while i + 3 <= list.len() {
                let name_type = *list.get(i)?;
                let name_len = be16(list, i + 1)? as usize;
                let name = list.get(i + 3..i + 3 + name_len)?;
                if name_type == 0 {
                    // A hostname is ASCII; refusing to print arbitrary bytes
                    // from the network keeps the terminal safe.
                    if name.iter().all(|b| b.is_ascii_graphic()) {
                        return Some(String::from_utf8_lossy(name).into_owned());
                    }
                    return None;
                }
                i += 3 + name_len;
            }
        }
        e += 4 + ext_len;
    }
    None
}

fn be16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset + 1)?,
    ]))
}

fn decode_http(payload: &[u8]) -> Option<String> {
    // Only look at the first line, and only a bounded amount of it.
    let end = payload
        .iter()
        .take(256)
        .position(|&b| b == b'\r' || b == b'\n')?;
    let line = std::str::from_utf8(&payload[..end]).ok()?;

    if line.starts_with("HTTP/") {
        return Some(format!(
            "response {}",
            line.trim_start_matches("HTTP/1.1 ")
                .trim_start_matches("HTTP/1.0 ")
        ));
    }
    for method in [
        "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ",
    ] {
        if line.starts_with(method) {
            return Some(line.to_string());
        }
    }
    None
}

fn well_known(port: u16) -> Option<&'static str> {
    Some(match port {
        20 | 21 => "FTP",
        22 => "SSH",
        23 => "TELNET",
        25 | 587 => "SMTP",
        67 | 68 => "DHCP",
        110 => "POP3",
        123 => "NTP",
        143 => "IMAP",
        161 | 162 => "SNMP",
        179 => "BGP",
        389 => "LDAP",
        443 => "HTTPS",
        445 => "SMB",
        514 => "SYSLOG",
        636 => "LDAPS",
        1194 => "OPENVPN",
        1433 => "MSSQL",
        3306 => "MYSQL",
        3389 => "RDP",
        5432 => "POSTGRES",
        6379 => "REDIS",
        8080 | 8000 | 3000 => "HTTP-ALT",
        9092 => "KAFKA",
        9200 => "ELASTIC",
        27017 => "MONGO",
        _ => return None,
    })
}

/// Renders bytes as a hex dump with an ASCII gutter, the way every packet
/// viewer does, because reading raw hex without the ASCII column is painful.
pub fn hex_dump(bytes: &[u8], max: usize) -> Vec<String> {
    let bytes = &bytes[..bytes.len().min(max)];
    let mut out = Vec::new();
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let mut hex = String::new();
        let mut ascii = String::new();
        for (j, b) in chunk.iter().enumerate() {
            if j == 8 {
                hex.push(' ');
            }
            hex.push_str(&format!("{b:02x} "));
            ascii.push(if b.is_ascii_graphic() || *b == b' ' {
                *b as char
            } else {
                '.'
            });
        }
        out.push(format!("{:08x}  {:<49} |{}|", i * 16, hex, ascii));
    }
    out
}
