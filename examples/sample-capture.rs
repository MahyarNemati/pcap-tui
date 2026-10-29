//! Writes a small capture file, so the viewer can be tried without having to
//! capture traffic first.
//!
//! The file is built from the pcap spec rather than by shelling out to
//! tcpdump, which means `cargo run --example sample-capture` works on a
//! machine with no libpcap, no root and no network.
//!
//!     cargo run --example sample-capture -- sample.pcap
//!     cargo run -- sample.pcap

use std::io::Write;

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "sample.pcap".into());
    let mut out = Vec::new();

    // File header: little-endian, microseconds, Ethernet.
    out.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // thiszone
    out.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    out.extend_from_slice(&262_144u32.to_le_bytes()); // snaplen
    out.extend_from_slice(&1u32.to_le_bytes()); // DLT_EN10MB

    let client = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    let router = [0x02, 0x00, 0x00, 0x00, 0x00, 0xfe];
    let mut t = 1_700_000_000u32;
    let mut usec = 0u32;
    let mut push = |data: Vec<u8>, dt_usec: u32, out: &mut Vec<u8>| {
        usec += dt_usec;
        t += usec / 1_000_000;
        usec %= 1_000_000;
        out.extend_from_slice(&t.to_le_bytes());
        out.extend_from_slice(&usec.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&data);
    };

    // A DNS lookup, then the TCP handshake and TLS ClientHello that follows
    // it: the shape of every page load, which is what makes it a useful
    // thing to look at first.
    push(
        eth(
            client,
            router,
            0x0800,
            &ip(
                17,
                [10, 0, 0, 1],
                [10, 0, 0, 53],
                &udp(54_120, 53, &dns("www.example.com")),
            ),
        ),
        0,
        &mut out,
    );
    push(
        eth(
            router,
            client,
            0x0800,
            &ip(
                17,
                [10, 0, 0, 53],
                [10, 0, 0, 1],
                &udp(
                    53,
                    54_120,
                    &dns_response("www.example.com", [93, 184, 216, 34]),
                ),
            ),
        ),
        12_400,
        &mut out,
    );
    push(
        eth(
            client,
            router,
            0x0800,
            &ip(
                6,
                [10, 0, 0, 1],
                [93, 184, 216, 34],
                &tcp(49_812, 443, 1, 0, 0x02, &[]),
            ),
        ),
        900,
        &mut out,
    );
    push(
        eth(
            router,
            client,
            0x0800,
            &ip(
                6,
                [93, 184, 216, 34],
                [10, 0, 0, 1],
                &tcp(443, 49_812, 9_001, 2, 0x12, &[]),
            ),
        ),
        18_300,
        &mut out,
    );
    push(
        eth(
            client,
            router,
            0x0800,
            &ip(
                6,
                [10, 0, 0, 1],
                [93, 184, 216, 34],
                &tcp(49_812, 443, 2, 9_002, 0x10, &[]),
            ),
        ),
        150,
        &mut out,
    );
    push(
        eth(
            client,
            router,
            0x0800,
            &ip(
                6,
                [10, 0, 0, 1],
                [93, 184, 216, 34],
                &tcp(
                    49_812,
                    443,
                    2,
                    9_002,
                    0x18,
                    &client_hello("www.example.com"),
                ),
            ),
        ),
        400,
        &mut out,
    );
    // An unencrypted request to a local service, which is the one case where
    // the payload is readable.
    push(
        eth(client, router, 0x0800, &ip(6, [10, 0, 0, 1], [10, 0, 0, 7], &tcp(49_813, 80, 1, 1, 0x18, b"GET /healthz HTTP/1.1\r\nHost: metrics.internal\r\nUser-Agent: curl/8.4.0\r\n\r\n"))),
        35_000,
        &mut out,
    );
    // A ping, and an ARP broadcast of the kind every network is full of.
    push(
        eth(
            client,
            router,
            0x0800,
            &ip(1, [10, 0, 0, 1], [8, 8, 8, 8], &icmp_echo(0x2a1f, 1)),
        ),
        120_000,
        &mut out,
    );
    push(
        eth(
            client,
            [0xff; 6],
            0x0806,
            &arp(client, [10, 0, 0, 1], [10, 0, 0, 42]),
        ),
        400_000,
        &mut out,
    );

    let mut f = std::fs::File::create(&path).expect("create the capture file");
    f.write_all(&out).expect("write the capture file");
    println!("wrote {path} ({} bytes, 9 packets)", out.len());
    println!("now try:  cargo run -- {path}");
    println!("      or: cargo run -- summary {path}");
}

fn eth(src: [u8; 6], dst: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&dst);
    v.extend_from_slice(&src);
    v.extend_from_slice(&ethertype.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

fn ip(protocol: u8, src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut h = vec![0u8; 20];
    h[0] = 0x45;
    h[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    h[4..6].copy_from_slice(&0x4d2u16.to_be_bytes());
    h[8] = 64;
    h[9] = protocol;
    h[12..16].copy_from_slice(&src);
    h[16..20].copy_from_slice(&dst);
    let sum = checksum(&h);
    h[10..12].copy_from_slice(&sum.to_be_bytes());
    h.extend_from_slice(payload);
    h
}

fn udp(src: u16, dst: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&src.to_be_bytes());
    v.extend_from_slice(&dst.to_be_bytes());
    v.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    v.extend_from_slice(&0u16.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

fn tcp(src: u16, dst: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut h = vec![0u8; 20];
    h[0..2].copy_from_slice(&src.to_be_bytes());
    h[2..4].copy_from_slice(&dst.to_be_bytes());
    h[4..8].copy_from_slice(&seq.to_be_bytes());
    h[8..12].copy_from_slice(&ack.to_be_bytes());
    h[12] = 5 << 4;
    h[13] = flags;
    h[14..16].copy_from_slice(&64_240u16.to_be_bytes());
    h.extend_from_slice(payload);
    h
}

fn name_labels(name: &str) -> Vec<u8> {
    let mut v = Vec::new();
    for label in name.split('.') {
        v.push(label.len() as u8);
        v.extend_from_slice(label.as_bytes());
    }
    v.push(0);
    v
}

fn dns(name: &str) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&0x1a2bu16.to_be_bytes());
    v.extend_from_slice(&0x0100u16.to_be_bytes());
    v.extend_from_slice(&1u16.to_be_bytes());
    v.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    v.extend_from_slice(&name_labels(name));
    v.extend_from_slice(&1u16.to_be_bytes()); // A
    v.extend_from_slice(&1u16.to_be_bytes()); // IN
    v
}

fn dns_response(name: &str, addr: [u8; 4]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&0x1a2bu16.to_be_bytes());
    v.extend_from_slice(&0x8180u16.to_be_bytes()); // response, recursion available
    v.extend_from_slice(&1u16.to_be_bytes()); // questions
    v.extend_from_slice(&1u16.to_be_bytes()); // answers
    v.extend_from_slice(&[0, 0, 0, 0]);
    let labels = name_labels(name);
    v.extend_from_slice(&labels);
    v.extend_from_slice(&1u16.to_be_bytes());
    v.extend_from_slice(&1u16.to_be_bytes());
    // The answer repeats the name uncompressed: a pointer would be smaller,
    // but this file is meant to be readable rather than minimal.
    v.extend_from_slice(&labels);
    v.extend_from_slice(&1u16.to_be_bytes());
    v.extend_from_slice(&1u16.to_be_bytes());
    v.extend_from_slice(&300u32.to_be_bytes()); // TTL
    v.extend_from_slice(&4u16.to_be_bytes());
    v.extend_from_slice(&addr);
    v
}

fn client_hello(server_name: &str) -> Vec<u8> {
    let mut sni = Vec::new();
    sni.extend_from_slice(&((server_name.len() + 3) as u16).to_be_bytes());
    sni.push(0);
    sni.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
    sni.extend_from_slice(server_name.as_bytes());

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&0u16.to_be_bytes());
    extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni);

    let mut hello = Vec::new();
    hello.extend_from_slice(&0x0303u16.to_be_bytes());
    hello.extend_from_slice(&[0x5a; 32]);
    hello.push(0);
    hello.extend_from_slice(&2u16.to_be_bytes());
    hello.extend_from_slice(&0x1301u16.to_be_bytes());
    hello.push(1);
    hello.push(0);
    hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    hello.extend_from_slice(&extensions);

    let mut handshake = vec![0x01];
    handshake.extend_from_slice(&(hello.len() as u32).to_be_bytes()[1..]);
    handshake.extend_from_slice(&hello);

    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

fn icmp_echo(id: u16, seq: u16) -> Vec<u8> {
    let mut v = vec![8, 0, 0, 0];
    v.extend_from_slice(&id.to_be_bytes());
    v.extend_from_slice(&seq.to_be_bytes());
    v.extend_from_slice(b"abcdefghijklmnopqrstuvwabcdefghi");
    let sum = checksum(&v);
    v[2..4].copy_from_slice(&sum.to_be_bytes());
    v
}

fn arp(sender_mac: [u8; 6], sender_ip: [u8; 4], target_ip: [u8; 4]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&1u16.to_be_bytes());
    v.extend_from_slice(&0x0800u16.to_be_bytes());
    v.push(6);
    v.push(4);
    v.extend_from_slice(&1u16.to_be_bytes());
    v.extend_from_slice(&sender_mac);
    v.extend_from_slice(&sender_ip);
    v.extend_from_slice(&[0u8; 6]);
    v.extend_from_slice(&target_ip);
    v
}

fn checksum(bytes: &[u8]) -> u16 {
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
