//! Tests for the capture-file readers.
//!
//! Each fixture is built byte by byte from the file-format spec, so a test
//! that passes says the reader agrees with the format rather than with
//! itself.

mod support;

use std::time::{Duration, UNIX_EPOCH};

use pcap_tui::pcap::{LinkType, Reader};
use support::*;

fn read_all(bytes: Vec<u8>) -> Vec<pcap_tui::pcap::Packet> {
    let mut reader = Reader::from_reader(Box::new(std::io::Cursor::new(bytes))).expect("open");
    let mut out = Vec::new();
    while let Some(p) = reader.next_packet().expect("read packet") {
        out.push(p);
    }
    out
}

#[test]
fn reads_little_endian_microsecond_pcap() {
    let mut w = PcapWriter::new(1);
    w.push(1_700_000_000, 250_000, b"hello");
    w.push(1_700_000_001, 0, b"world!");

    let reader = Reader::from_reader(Box::new(std::io::Cursor::new(w.bytes.clone()))).unwrap();
    assert_eq!(reader.format_name(), "pcap");
    assert!(!reader.big_endian());
    assert_eq!(reader.link_type(), LinkType::Ethernet);

    let packets = read_all(w.bytes);
    assert_eq!(packets.len(), 2);
    assert_eq!(packets[0].number, 1);
    assert_eq!(packets[0].data, b"hello");
    assert_eq!(
        packets[0].timestamp,
        UNIX_EPOCH + Duration::new(1_700_000_000, 250_000_000)
    );
    assert_eq!(packets[1].number, 2);
    assert_eq!(packets[1].data, b"world!");
}

#[test]
fn reads_big_endian_pcap_identically() {
    // The same logical capture written the other way round must decode to
    // the same packets. Byte-order bugs are the most common reason a reader
    // works on the author's machine and nowhere else.
    let mut le = PcapWriter::new(1);
    le.push(1_700_000_000, 250_000, b"hello");
    let mut be = PcapWriter::big_endian(1);
    be.push(1_700_000_000, 250_000, b"hello");

    assert_ne!(le.bytes, be.bytes, "the fixtures should differ on disk");

    let reader = Reader::from_reader(Box::new(std::io::Cursor::new(be.bytes.clone()))).unwrap();
    assert!(reader.big_endian());
    drop(reader);

    assert_eq!(
        read_all(le.bytes)[0].timestamp,
        read_all(be.bytes)[0].timestamp
    );
}

#[test]
fn nanosecond_pcap_keeps_sub_microsecond_precision() {
    let mut w = PcapWriter::nanos(1);
    w.push(1_700_000_000, 123_456_789, b"x");
    let packets = read_all(w.bytes);
    assert_eq!(
        packets[0].timestamp,
        UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_789),
        "a nanosecond file must not be read as microseconds"
    );
}

#[test]
fn truncated_packets_are_flagged_not_hidden() {
    // A short snaplen stores fewer bytes than the packet had on the wire.
    // Reporting the captured bytes as the whole packet would silently
    // mislead; the packet knows it is incomplete.
    let mut w = PcapWriter::new(1);
    w.push_truncated(1, 0, &[0xaa; 64], 1500);
    let packets = read_all(w.bytes);
    assert_eq!(packets[0].data.len(), 64);
    assert_eq!(packets[0].original_len, 1500);
    assert!(packets[0].truncated());
}

#[test]
fn rejects_an_implausible_packet_length_instead_of_allocating() {
    // A corrupt record claiming 4 GiB must not become a 4 GiB allocation.
    let mut w = PcapWriter::new(1);
    w.raw(&1u32.to_le_bytes()); // ts_sec
    w.raw(&0u32.to_le_bytes()); // ts_usec
    w.raw(&0xffff_ffffu32.to_le_bytes()); // incl_len
    w.raw(&0xffff_ffffu32.to_le_bytes()); // orig_len

    let mut reader = Reader::from_reader(Box::new(std::io::Cursor::new(w.bytes))).unwrap();
    let err = reader.next_packet().expect_err("should refuse");
    assert!(
        err.to_string().contains("exceeds"),
        "unhelpful error: {err}"
    );
}

#[test]
fn a_truncated_file_is_an_error_not_a_silent_short_read() {
    let mut w = PcapWriter::new(1);
    w.push(1, 0, &[0xaa; 32]);
    let mut bytes = w.bytes;
    bytes.truncate(bytes.len() - 10); // lose the tail of the packet data

    let mut reader = Reader::from_reader(Box::new(std::io::Cursor::new(bytes))).unwrap();
    let err = reader
        .next_packet()
        .expect_err("should report the truncation");
    assert!(
        err.to_string().contains("truncated"),
        "unhelpful error: {err}"
    );
}

#[test]
fn an_empty_file_and_a_garbage_file_both_report_clearly() {
    let err = Reader::from_reader(Box::new(std::io::Cursor::new(Vec::new()))).expect_err("empty");
    assert!(err.to_string().contains("empty"), "unhelpful error: {err}");

    let err = Reader::from_reader(Box::new(std::io::Cursor::new(b"not a capture".to_vec())))
        .expect_err("garbage");
    assert!(
        err.to_string().contains("unrecognised"),
        "unhelpful error: {err}"
    );
}

#[test]
fn a_header_only_pcap_reads_as_zero_packets() {
    let w = PcapWriter::new(1);
    assert!(read_all(w.bytes).is_empty());
}

#[test]
fn link_type_comes_from_the_file_header() {
    for (dlt, expected) in [
        (1u32, LinkType::Ethernet),
        (0, LinkType::Null),
        (101, LinkType::Raw),
        (113, LinkType::LinuxSll),
        (999, LinkType::Other(999)),
    ] {
        let w = PcapWriter::new(dlt);
        let reader = Reader::from_reader(Box::new(std::io::Cursor::new(w.bytes))).unwrap();
        assert_eq!(reader.link_type(), expected, "DLT {dlt}");
    }
}

// ------------------------------------------------------------------ pcapng

#[test]
fn reads_pcapng_enhanced_packet_blocks() {
    let mut w = PcapngWriter::new();
    let iface = w.interface(1, 262_144);
    w.packet(iface, 1_700_000_000_250_000, b"hello");
    w.packet(iface, 1_700_000_001_000_000, b"world!");

    let reader = Reader::from_reader(Box::new(std::io::Cursor::new(w.bytes.clone()))).unwrap();
    assert_eq!(reader.format_name(), "pcapng");
    assert_eq!(reader.link_type(), LinkType::Ethernet);
    drop(reader);

    let packets = read_all(w.bytes);
    assert_eq!(packets.len(), 2);
    assert_eq!(packets[0].data, b"hello");
    assert_eq!(
        packets[0].timestamp,
        UNIX_EPOCH + Duration::from_micros(1_700_000_000_250_000)
    );
    assert_eq!(packets[1].data, b"world!");
}

#[test]
fn pcapng_block_padding_is_not_mistaken_for_packet_data() {
    // Block bodies are padded to a 4-byte boundary. A reader that trusts the
    // body length rather than the captured length appends up to 3 zero bytes
    // to every odd-length packet.
    let mut w = PcapngWriter::new();
    let iface = w.interface(1, 262_144);
    w.packet(iface, 0, b"odd"); // 3 bytes, so one byte of padding
    let packets = read_all(w.bytes);
    assert_eq!(packets[0].data, b"odd");
}

#[test]
fn pcapng_simple_packet_blocks_use_the_original_length() {
    // A simple packet block carries no captured length, so the padding can
    // only be told apart from the data by the original length.
    let mut w = PcapngWriter::new();
    w.interface(1, 262_144);
    w.simple_packet(b"five!");
    let packets = read_all(w.bytes);
    assert_eq!(packets[0].data, b"five!");
    assert_eq!(packets[0].original_len, 5);
}

#[test]
fn pcapng_unknown_blocks_are_skipped() {
    // Tolerating unknown block types is the whole reason pcapng is
    // extensible; a reader that fails here cannot read a newer capture.
    let mut w = PcapngWriter::new();
    let iface = w.interface(1, 262_144);
    w.unknown_block(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33]);
    w.packet(iface, 0, b"after");
    let packets = read_all(w.bytes);
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].data, b"after");
}

#[test]
fn pcapng_packets_take_the_link_type_of_their_interface() {
    // A pcapng file can mix interfaces, so the link type is per packet. Using
    // the first interface's type for all of them misdecodes every packet on
    // the others.
    let mut w = PcapngWriter::new();
    let eth = w.interface(1, 262_144);
    let raw = w.interface(101, 262_144);
    w.packet(eth, 0, b"ethernet-framed");
    w.packet(raw, 0, b"raw-ip-framed");

    let packets = read_all(w.bytes);
    assert_eq!(packets[0].link_type, LinkType::Ethernet);
    assert_eq!(packets[1].link_type, LinkType::Raw);
}

#[test]
fn rejects_an_implausible_pcapng_block_length() {
    let mut w = PcapngWriter::new();
    w.interface(1, 262_144);
    // A block claiming a length below the 12-byte minimum would make the
    // body length underflow.
    w.bytes.extend_from_slice(&0x0000_0006u32.to_le_bytes());
    w.bytes.extend_from_slice(&4u32.to_le_bytes());

    let mut reader = Reader::from_reader(Box::new(std::io::Cursor::new(w.bytes))).unwrap();
    let err = reader.next_packet().expect_err("should refuse");
    assert!(
        err.to_string().contains("implausible"),
        "unhelpful error: {err}"
    );
}

#[test]
fn an_enhanced_packet_block_that_lies_about_its_length_is_rejected() {
    let mut w = PcapngWriter::new();
    let iface = w.interface(1, 262_144);
    // Claim 400 captured bytes while storing 4.
    w.packet_truncated(iface, 0, b"four", 400);
    // packet_truncated sets original_len, not captured_len, so build the bad
    // block by hand: captured_len is the field a reader must bounds-check.
    let mut bad = PcapngWriter::new();
    bad.interface(1, 262_144);
    let mut body = Vec::new();
    body.extend_from_slice(&0u32.to_le_bytes()); // interface
    body.extend_from_slice(&0u32.to_le_bytes()); // ts high
    body.extend_from_slice(&0u32.to_le_bytes()); // ts low
    body.extend_from_slice(&400u32.to_le_bytes()); // captured_len: a lie
    body.extend_from_slice(&400u32.to_le_bytes()); // original_len
    body.extend_from_slice(b"four");
    let total = 12 + body.len() as u32;
    bad.bytes.extend_from_slice(&0x0000_0006u32.to_le_bytes());
    bad.bytes.extend_from_slice(&total.to_le_bytes());
    bad.bytes.extend_from_slice(&body);
    bad.bytes.extend_from_slice(&total.to_le_bytes());

    let mut reader = Reader::from_reader(Box::new(std::io::Cursor::new(bad.bytes))).unwrap();
    let err = reader.next_packet().expect_err("should refuse");
    assert!(err.to_string().contains("claims"), "unhelpful error: {err}");
}

#[test]
fn opens_a_file_from_disk() {
    let w = mixed_capture();
    let (_dir, path) = w.write_to_temp("mixed.pcap");
    let mut reader = Reader::open(&path).expect("open from disk");
    let mut n = 0;
    while reader.next_packet().unwrap().is_some() {
        n += 1;
    }
    assert_eq!(n, 6);
}

#[test]
fn opening_a_missing_file_names_the_path() {
    let err = Reader::open(std::path::Path::new("/nonexistent/capture.pcap")).expect_err("missing");
    assert!(
        err.to_string().contains("capture.pcap"),
        "the error should name the file: {err}"
    );
}
