//! Tests for the protocol decoders.
//!
//! The decoders run on bytes from the network, so the interesting cases are
//! the hostile ones: headers that claim to be longer than the packet, option
//! fields that point past the end, and names that loop. Those get as much
//! attention here as the happy path.

mod support;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::UNIX_EPOCH;

use pcap_tui::decode::{decode, hex_dump, Protocol};
use pcap_tui::pcap::{LinkType, Packet};
use support::*;

fn packet(link_type: LinkType, data: Vec<u8>) -> Packet {
    Packet {
        number: 1,
        timestamp: UNIX_EPOCH,
        original_len: data.len() as u32,
        data,
        link_type,
    }
}

fn eth(data: Vec<u8>) -> Packet {
    packet(LinkType::Ethernet, data)
}

#[test]
fn decodes_a_tcp_syn_over_ipv4() {
    let p = eth(ethernet(
        MAC_A,
        MAC_B,
        0x0800,
        &ipv4(
            Ipv4 {
                src: [192, 168, 1, 10],
                dst: [192, 168, 1, 1],
                protocol: 6,
                ttl: 64,
                ..Default::default()
            },
            &tcp(
                Tcp {
                    src_port: 51234,
                    dst_port: 443,
                    seq: 1000,
                    flags: TCP_SYN,
                    window: 64240,
                    ..Default::default()
                },
                &[],
            ),
        ),
    ));
    let d = decode(&p);

    assert_eq!(d.src_mac.map(|m| m.0), Some(MAC_A));
    assert_eq!(d.dst_mac.map(|m| m.0), Some(MAC_B));
    assert_eq!(d.ethertype, Some(0x0800));
    assert_eq!(d.src_ip, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))));
    assert_eq!(d.dst_ip, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    assert_eq!(d.ttl, Some(64));
    assert_eq!(d.protocol, Some(Protocol::Tcp));
    assert_eq!(d.src_port, Some(51234));
    assert_eq!(d.dst_port, Some(443));
    assert_eq!(d.seq, Some(1000));
    assert_eq!(d.window, Some(64240));
    let flags = d.tcp_flags.expect("flags");
    assert!(flags.syn && !flags.ack && !flags.fin);
    assert_eq!(d.flow(), "192.168.1.10:51234 → 192.168.1.1:443");
    assert!(
        d.info.contains("[S]"),
        "tcpdump-style flags expected: {}",
        d.info
    );
}

#[test]
fn tcp_flag_combinations_render_like_tcpdump() {
    for (bits, expected) in [
        (TCP_SYN, "[S]"),
        (TCP_SYN | TCP_ACK, "[S.]"),
        (TCP_ACK, "[.]"),
        (TCP_FIN | TCP_ACK, "[F.]"),
        (TCP_RST, "[R]"),
        (TCP_PSH | TCP_ACK, "[P.]"),
    ] {
        let p = eth(ethernet(
            MAC_A,
            MAC_B,
            0x0800,
            &ipv4(
                Ipv4::default(),
                &tcp(
                    Tcp {
                        flags: bits,
                        ..Default::default()
                    },
                    &[],
                ),
            ),
        ));
        let d = decode(&p);
        assert!(
            d.info.contains(expected),
            "flags {bits:#04x} should render {expected}, got {}",
            d.info
        );
    }
}

#[test]
fn tcp_options_do_not_shift_the_payload() {
    // The data offset says where the payload starts. A decoder that assumes
    // a 20-byte header reads the options as payload and then misidentifies
    // the application protocol.
    let payload = b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n";
    let p = eth(ethernet(
        MAC_A,
        MAC_B,
        0x0800,
        &ipv4(
            Ipv4::default(),
            &tcp(
                Tcp {
                    data_offset_words: 8,
                    flags: TCP_PSH | TCP_ACK,
                    ..Default::default()
                },
                payload,
            ),
        ),
    ));
    let d = decode(&p);
    assert_eq!(d.payload_len, payload.len());
    assert_eq!(d.top_protocol, "HTTP");
    assert!(d.info.contains("GET /health"), "{}", d.info);
}

#[test]
fn ipv4_options_do_not_shift_the_transport_header() {
    // IHL > 5 means the IP header carries options. Skipping a fixed 20 bytes
    // reads the options as a TCP header and produces nonsense ports.
    let p = eth(ethernet(
        MAC_A,
        MAC_B,
        0x0800,
        &ipv4(
            Ipv4 {
                ihl_words: 7,
                protocol: 6,
                ..Default::default()
            },
            &tcp(
                Tcp {
                    src_port: 1234,
                    dst_port: 5678,
                    ..Default::default()
                },
                &[],
            ),
        ),
    ));
    let d = decode(&p);
    assert_eq!(d.src_port, Some(1234));
    assert_eq!(d.dst_port, Some(5678));
}

#[test]
fn rejects_an_invalid_ipv4_header_length() {
    // IHL below 5 would make the header shorter than the fixed fields.
    let mut bytes = ipv4(Ipv4::default(), &[0u8; 8]);
    bytes[0] = 0x43; // version 4, IHL 3
    let p = eth(ethernet(MAC_A, MAC_B, 0x0800, &bytes));
    let d = decode(&p);
    assert!(d.info.contains("invalid IPv4 header length"), "{}", d.info);
    assert_eq!(
        d.src_port, None,
        "nothing should be decoded past a bad header"
    );
}

#[test]
fn an_ip_fragment_is_reported_as_one_and_not_decoded_further() {
    // Only the first fragment carries the transport header. Decoding the
    // middle of a fragmented packet as TCP yields invented ports.
    let p = eth(ethernet(
        MAC_A,
        MAC_B,
        0x0800,
        &ipv4(
            Ipv4 {
                protocol: 6,
                flags_and_offset: 185,
                ..Default::default()
            }, // offset 185 * 8
            &[0xaa; 40],
        ),
    ));
    let d = decode(&p);
    assert!(d.fragmented);
    assert_eq!(d.fragment_offset, 185);
    assert!(d.info.contains("fragment"), "{}", d.info);
    assert_eq!(
        d.src_port, None,
        "a non-first fragment has no ports to read"
    );
}

#[test]
fn decodes_udp_and_dns() {
    let p = eth(ethernet(
        MAC_A,
        MAC_B,
        0x0800,
        &ipv4(
            Ipv4 {
                protocol: 17,
                dst: [1, 1, 1, 1],
                ..Default::default()
            },
            &udp(40000, 53, &dns_query(0x1234, "www.example.com", 1)),
        ),
    ));
    let d = decode(&p);
    assert_eq!(d.protocol, Some(Protocol::Udp));
    assert_eq!(d.top_protocol, "DNS");
    assert!(d.info.contains("www.example.com"), "{}", d.info);
    assert!(d.info.contains("query"), "{}", d.info);
}

#[test]
fn mdns_is_distinguished_from_unicast_dns() {
    let p = eth(ethernet(
        MAC_A,
        MAC_B,
        0x0800,
        &ipv4(
            Ipv4 {
                protocol: 17,
                dst: [224, 0, 0, 251],
                ..Default::default()
            },
            &udp(5353, 5353, &dns_query(0, "_airplay._tcp.local", 12)),
        ),
    ));
    assert_eq!(decode(&p).top_protocol, "MDNS");
}

#[test]
fn a_dns_name_with_a_compression_loop_does_not_hang() {
    // A pointer to itself is the classic decompression bomb. The decoder
    // does not follow pointers at all, so this must terminate and say so
    // rather than spinning.
    let mut msg = dns_query(1, "a", 1);
    // Overwrite the question name with a pointer back to offset 12.
    msg[12] = 0xc0;
    msg[13] = 0x0c;
    let p = eth(ethernet(
        MAC_A,
        MAC_B,
        0x0800,
        &ipv4(
            Ipv4 {
                protocol: 17,
                ..Default::default()
            },
            &udp(40000, 53, &msg),
        ),
    ));
    let d = decode(&p);
    assert_eq!(d.top_protocol, "DNS");
    assert!(!d.info.is_empty());
}

#[test]
fn a_dns_name_whose_label_runs_past_the_end_is_handled() {
    let mut msg = dns_query(1, "example", 1);
    msg[12] = 200; // a label longer than the message
    let p = eth(ethernet(
        MAC_A,
        MAC_B,
        0x0800,
        &ipv4(
            Ipv4 {
                protocol: 17,
                ..Default::default()
            },
            &udp(40000, 53, &msg),
        ),
    ));
    let d = decode(&p);
    assert!(
        d.info.contains("unparseable") || d.info.contains("query"),
        "{}",
        d.info
    );
}

#[test]
fn identifies_tls_by_content_not_by_port() {
    // TLS on a non-standard port is the normal case for anything modern, so
    // identification must come from the record header.
    let p = eth(ethernet(
        MAC_A,
        MAC_B,
        0x0800,
        &ipv4(
            Ipv4::default(),
            &tcp(
                Tcp {
                    dst_port: 8443,
                    flags: TCP_PSH | TCP_ACK,
                    ..Default::default()
                },
                &tls_client_hello("example.com"),
            ),
        ),
    ));
    let d = decode(&p);
    assert_eq!(d.top_protocol, "TLS");
    assert!(d.info.contains("ClientHello"), "{}", d.info);
}

#[test]
fn a_well_known_port_is_labelled_as_a_guess() {
    // When only the port is known, the summary says so, because a service on
    // a well-known port is a convention and not a fact.
    let p = eth(ethernet(
        MAC_A,
        MAC_B,
        0x0800,
        &ipv4(
            Ipv4 {
                protocol: 17,
                ..Default::default()
            },
            &udp(
                12345,
                123,
                &[0x23, 0x00, 0x06, 0xec, 0x00, 0x00, 0x00, 0x00],
            ),
        ),
    ));
    let d = decode(&p);
    assert!(
        d.info.contains("by port"),
        "the guess should be visible: {}",
        d.info
    );
}

#[test]
fn decodes_icmp_echo_and_unreachable() {
    let p = eth(ethernet(
        MAC_A,
        MAC_B,
        0x0800,
        &ipv4(
            Ipv4 {
                protocol: 1,
                ..Default::default()
            },
            &icmp_echo_request(0x1234, 7, b"ping"),
        ),
    ));
    let d = decode(&p);
    assert_eq!(d.protocol, Some(Protocol::Icmp));
    assert!(d.info.contains("echo request"), "{}", d.info);
    assert!(d.info.contains("id=4660"), "{}", d.info);

    // Type 3 code 3: port unreachable.
    let p = eth(ethernet(
        MAC_A,
        MAC_B,
        0x0800,
        &ipv4(
            Ipv4 {
                protocol: 1,
                ..Default::default()
            },
            &[3, 3, 0, 0, 0, 0, 0, 0],
        ),
    ));
    assert!(
        decode(&p).info.contains("unreachable"),
        "{}",
        decode(&p).info
    );
}

#[test]
fn decodes_arp_requests_and_replies() {
    let p = eth(ethernet(
        MAC_A,
        [0xff; 6],
        0x0806,
        &arp_request(MAC_A, [10, 0, 0, 1], [10, 0, 0, 254]),
    ));
    let d = decode(&p);
    assert_eq!(d.top_protocol, "ARP");
    assert!(d.info.contains("10.0.0.254"), "{}", d.info);
    assert!(d.info.contains("10.0.0.1"), "{}", d.info);
}

#[test]
fn decodes_ipv6_with_an_extension_header_chain() {
    // The transport header sits after a chain of extension headers of
    // varying length; a decoder that assumes 40 bytes reads the chain as
    // TCP.
    let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
    let mut payload = ext_header(60, 8); // hop-by-hop → destination options
    payload.extend_from_slice(&ext_header(6, 0)); // destination options → TCP
    payload.extend_from_slice(&tcp(
        Tcp {
            src_port: 40000,
            dst_port: 993,
            flags: TCP_ACK,
            ..Default::default()
        },
        &[],
    ));
    let p = eth(ethernet(
        MAC_A,
        MAC_B,
        0x86dd,
        &ipv6(src.octets(), dst.octets(), 0, &payload),
    ));
    let d = decode(&p);
    assert_eq!(d.src_ip, Some(IpAddr::V6(src)));
    assert_eq!(d.protocol, Some(Protocol::Tcp));
    assert_eq!(d.dst_port, Some(993));
    assert_eq!(
        d.flow(),
        "[2001:db8::1]:40000 → [2001:db8::2]:993",
        "IPv6 endpoints need brackets so the port colon is unambiguous"
    );
}

#[test]
fn an_endless_ipv6_extension_chain_is_cut_off() {
    // A chain of zero-length headers pointing onwards forever would loop. A
    // bound on the chain length is the only safe answer.
    let mut payload = Vec::new();
    for _ in 0..200 {
        payload.extend_from_slice(&ext_header(60, 0)); // destination options, repeating
    }
    let p = eth(ethernet(
        MAC_A,
        MAC_B,
        0x86dd,
        &ipv6([0x20; 16], [0x21; 16], 60, &payload),
    ));
    let d = decode(&p); // must simply return
    assert!(
        d.info.contains("nested") || d.info.contains("truncated"),
        "the limit should be reported: {}",
        d.info
    );
}

#[test]
fn decodes_vlan_and_qinq_tags() {
    let inner = ipv4(
        Ipv4 {
            protocol: 6,
            ..Default::default()
        },
        &tcp(
            Tcp {
                dst_port: 22,
                ..Default::default()
            },
            &[],
        ),
    );
    let single = ethernet(MAC_A, MAC_B, 0x8100, &vlan(100, 0x0800, &inner));
    let d = decode(&eth(single));
    assert_eq!(d.dst_port, Some(22), "a single VLAN tag should be skipped");

    // QinQ: an outer 802.1ad tag wrapping an inner 802.1Q tag.
    let double = ethernet(
        MAC_A,
        MAC_B,
        0x88a8,
        &vlan(10, 0x8100, &vlan(20, 0x0800, &inner)),
    );
    let d = decode(&eth(double));
    assert_eq!(d.dst_port, Some(22), "stacked VLAN tags should be skipped");
}

#[test]
fn raw_ip_and_loopback_link_types_skip_the_right_number_of_bytes() {
    let ip = ipv4(
        Ipv4 {
            protocol: 17,
            ..Default::default()
        },
        &udp(5000, 5001, b"payload"),
    );

    let d = decode(&packet(LinkType::Raw, ip.clone()));
    assert_eq!(d.src_port, Some(5000), "raw IP has no link header");

    // DLT_NULL prefixes a 4-byte address family.
    let mut null = vec![2, 0, 0, 0];
    null.extend_from_slice(&ip);
    let d = decode(&packet(LinkType::Null, null));
    assert_eq!(d.src_port, Some(5000), "loopback has a 4-byte header");

    // Linux cooked capture prefixes 16 bytes.
    let mut sll = vec![0u8; 16];
    sll[14] = 0x08; // protocol: IPv4
    sll[15] = 0x00;
    sll.extend_from_slice(&ip);
    let d = decode(&packet(LinkType::LinuxSll, sll));
    assert_eq!(d.src_port, Some(5000), "Linux cooked has a 16-byte header");
}

#[test]
fn every_truncation_point_is_survivable() {
    // A packet can be cut short anywhere: by a small snaplen, by a corrupt
    // file, or by an attacker. Decoding each prefix of a real packet must
    // never panic, which is the property that matters more than any
    // individual field being right.
    let full = ethernet(
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
                    data_offset_words: 8,
                    flags: TCP_PSH | TCP_ACK,
                    ..Default::default()
                },
                &tls_client_hello("example.com"),
            ),
        ),
    );
    for n in 0..=full.len() {
        let d = decode(&eth(full[..n].to_vec()));
        // Whatever it decodes, it must say something.
        assert!(
            !d.info.is_empty() || !d.top_protocol.is_empty(),
            "silent at {n} bytes"
        );
    }
}

#[test]
fn arbitrary_bytes_never_panic_the_decoder() {
    // A cheap stand-in for fuzzing: a deterministic pseudo-random sweep over
    // lengths and contents, decoded under every link type.
    let mut state = 0x243f_6a88_85a3_08d3u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for link in [
        LinkType::Ethernet,
        LinkType::Raw,
        LinkType::Null,
        LinkType::LinuxSll,
    ] {
        for len in 0..200usize {
            let data: Vec<u8> = (0..len).map(|_| (next() & 0xff) as u8).collect();
            let _ = decode(&packet(link, data));
        }
    }
}

#[test]
fn hex_dump_is_offset_hex_and_ascii() {
    let lines = hex_dump(b"ABCDEFGHIJKLMNOP\x00\x01", 512);
    assert_eq!(lines.len(), 2);
    assert!(lines[0].starts_with("00000000  "), "{}", lines[0]);
    assert!(lines[0].contains("41 42 43"), "{}", lines[0]);
    assert!(lines[0].ends_with("|ABCDEFGHIJKLMNOP|"), "{}", lines[0]);
    assert!(lines[1].starts_with("00000010  "), "{}", lines[1]);
    // Unprintable bytes become dots rather than breaking the alignment.
    assert!(lines[1].contains("|..|"), "{}", lines[1]);
}

#[test]
fn hex_dump_respects_its_limit() {
    let lines = hex_dump(&[0u8; 4096], 64);
    assert_eq!(lines.len(), 4, "64 bytes is four 16-byte rows");
}

#[test]
fn a_packet_with_no_network_layer_still_decodes_to_something() {
    let d = decode(&eth(Vec::new()));
    assert!(!d.info.is_empty());
    assert_eq!(d.flow(), "? → ?");
}

#[test]
fn the_tls_sni_host_is_reported() {
    // The SNI is the only plaintext hostname in a modern TLS connection, so
    // showing it is most of the value of decoding TLS at all.
    let p = eth(ethernet(
        MAC_A,
        MAC_B,
        0x0800,
        &ipv4(
            Ipv4::default(),
            &tcp(
                Tcp {
                    dst_port: 443,
                    flags: TCP_PSH | TCP_ACK,
                    ..Default::default()
                },
                &tls_client_hello("login.example.org"),
            ),
        ),
    ));
    let d = decode(&p);
    assert_eq!(d.top_protocol, "TLS");
    assert!(d.info.contains("login.example.org"), "{}", d.info);
}

#[test]
fn a_client_hello_truncated_inside_the_sni_does_not_panic() {
    // Every length in a ClientHello comes off the wire. Each prefix of a
    // real one must be survivable.
    let hello = tls_client_hello("example.com");
    for n in 0..=hello.len() {
        let p = eth(ethernet(
            MAC_A,
            MAC_B,
            0x0800,
            &ipv4(
                Ipv4::default(),
                &tcp(
                    Tcp {
                        dst_port: 443,
                        flags: TCP_PSH,
                        ..Default::default()
                    },
                    &hello[..n],
                ),
            ),
        ));
        let _ = decode(&p);
    }
}

#[test]
fn a_hostname_with_control_bytes_is_not_printed() {
    // A server name is attacker-controlled and ends up on a terminal, where
    // escape sequences can move the cursor or change the title. Anything
    // that is not printable ASCII is dropped rather than shown.
    let mut hello = tls_client_hello("aaaaaaaaaaa");
    let at = hello
        .windows(11)
        .position(|w| w == b"aaaaaaaaaaa")
        .expect("the fixture should contain the name");
    hello[at..at + 11].copy_from_slice(b"\x1b[2Jevil.co");
    let p = eth(ethernet(
        MAC_A,
        MAC_B,
        0x0800,
        &ipv4(
            Ipv4::default(),
            &tcp(
                Tcp {
                    dst_port: 443,
                    flags: TCP_PSH,
                    ..Default::default()
                },
                &hello,
            ),
        ),
    ));
    let d = decode(&p);
    assert_eq!(d.top_protocol, "TLS");
    assert!(
        !d.info.contains('\x1b'),
        "an escape sequence reached the summary: {:?}",
        d.info
    );
}

#[test]
fn decodes_an_http_request_and_a_response() {
    for (payload, expected) in [
        (
            &b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"[..],
            "GET /index.html",
        ),
        (
            &b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"[..],
            "404",
        ),
    ] {
        let p = eth(ethernet(
            MAC_A,
            MAC_B,
            0x0800,
            &ipv4(
                Ipv4::default(),
                &tcp(
                    Tcp {
                        dst_port: 80,
                        flags: TCP_PSH | TCP_ACK,
                        ..Default::default()
                    },
                    payload,
                ),
            ),
        ));
        let d = decode(&p);
        assert_eq!(d.top_protocol, "HTTP");
        assert!(d.info.contains(expected), "{}", d.info);
    }
}

#[test]
fn a_udp_header_that_claims_more_than_it_has_is_not_trusted() {
    // The UDP length field covers the header plus payload. A decoder that
    // subtracts 8 and uses the result as a slice length reads past the end.
    let mut datagram = udp(1000, 2000, b"four");
    datagram[4..6].copy_from_slice(&9999u16.to_be_bytes());
    let p = eth(ethernet(
        MAC_A,
        MAC_B,
        0x0800,
        &ipv4(
            Ipv4 {
                protocol: 17,
                ..Default::default()
            },
            &datagram,
        ),
    ));
    let d = decode(&p);
    assert_eq!(d.src_port, Some(1000));
    assert!(
        d.payload_len <= 4,
        "payload length should be bounded by the packet"
    );
}

#[test]
fn arp_endpoints_are_filled_in_from_the_protocol_addresses() {
    // ARP has no IP header, but it does carry IP addresses. Leaving them
    // unset makes every ARP packet an anonymous row that no address filter
    // can find.
    let p = eth(ethernet(
        MAC_A,
        [0xff; 6],
        0x0806,
        &arp_request(MAC_A, [10, 0, 0, 1], [10, 0, 0, 42]),
    ));
    let d = decode(&p);
    assert_eq!(d.src_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    assert_eq!(d.dst_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42))));
    assert_eq!(d.flow(), "10.0.0.1 → 10.0.0.42");
}
