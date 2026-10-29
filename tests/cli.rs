//! Tests for the non-interactive commands, run against the real binary.
//!
//! `summary` and `dump` exist so the tool is useful in a pipeline, which a
//! TUI can never be. Running the actual binary is the only way to check that
//! the argument parsing, the exit codes and the output all line up.

mod support;

use std::path::Path;
use std::process::{Command, Output};

use support::*;

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pcap-tui"))
        .args(args)
        .output()
        .expect("run pcap-tui")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn fixture(name: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    mixed_capture().write_to_temp(name)
}

#[test]
fn summary_reports_counts_protocols_and_conversations() {
    let (_dir, path) = fixture("mixed.pcap");
    let out = run(&["summary", path.to_str().unwrap()]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);

    assert!(text.contains("packets:  6"), "{text}");
    assert!(text.contains("format:"), "{text}");
    assert!(text.contains("Ethernet"), "{text}");
    assert!(text.contains("protocols"), "{text}");
    assert!(text.contains("DNS"), "{text}");
    assert!(text.contains("conversations"), "{text}");
    assert!(
        text.contains('⇄'),
        "conversations should be bidirectional: {text}"
    );
    assert!(text.contains("rate:"), "{text}");
}

#[test]
fn summary_top_limits_the_conversation_list() {
    let (_dir, path) = fixture("mixed.pcap");
    let out = run(&["summary", path.to_str().unwrap(), "--top", "1"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    let rows = text.lines().filter(|l| l.contains('⇄')).count();
    assert_eq!(rows, 1, "{text}");
}

#[test]
fn dump_prints_one_line_per_packet() {
    let (_dir, path) = fixture("mixed.pcap");
    let out = run(&["dump", path.to_str().unwrap()]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 6, "{lines:#?}");
    assert!(lines[0].contains("10.0.0.1:50000"), "{}", lines[0]);
    assert!(lines[2].contains("DNS"), "{}", lines[2]);
}

#[test]
fn dump_applies_a_filter() {
    let (_dir, path) = fixture("mixed.pcap");
    let out = run(&["dump", path.to_str().unwrap(), "--filter", "proto:dns"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out).lines().count(), 1, "{}", stdout(&out));
}

#[test]
fn dump_rejects_a_filter_typo_with_a_nonzero_exit() {
    // Silently printing nothing would look like a capture with no matching
    // packets. In a pipeline that difference matters.
    let (_dir, path) = fixture("mixed.pcap");
    let out = run(&["dump", path.to_str().unwrap(), "--filter", "prot:dns"]);
    assert!(!out.status.success(), "should fail: {}", stdout(&out));
    assert!(
        stderr(&out).contains("unknown filter key"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn a_packet_limit_stops_early() {
    let (_dir, path) = fixture("mixed.pcap");
    let out = run(&["dump", path.to_str().unwrap(), "-n", "2"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out).lines().count(), 2);
}

#[test]
fn a_missing_file_fails_and_names_the_path() {
    let out = run(&["summary", "/nonexistent/nope.pcap"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("nope.pcap"), "{}", stderr(&out));
}

#[test]
fn a_file_that_is_not_a_capture_fails_clearly() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("notes.txt");
    std::fs::write(&path, b"this is not a capture file").unwrap();
    let out = run(&["summary", path.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("unrecognised"), "{}", stderr(&out));
}

#[test]
fn no_arguments_explains_what_to_do_instead_of_opening_an_empty_viewer() {
    let out = run(&[]);
    assert!(!out.status.success());
    let text = stderr(&out);
    assert!(
        text.contains("--help") || text.contains("capture file"),
        "{text}"
    );
}

#[test]
fn help_and_version_work() {
    let out = run(&["--help"]);
    assert!(out.status.success());
    let text = stdout(&out);
    assert!(text.contains("EXAMPLES"), "{text}");
    assert!(
        text.contains("libpcap"),
        "the live-capture caveat should be stated: {text}"
    );

    let out = run(&["--version"]);
    assert!(out.status.success());
    assert!(stdout(&out).contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn live_capture_says_how_to_enable_it_when_it_is_not_compiled_in() {
    // The default build has no libpcap. Asking for live capture must explain
    // that rather than failing with a linker-flavoured error.
    let out = run(&["live", "en0"]);
    if cfg!(feature = "live") {
        // With the feature on, this needs root; either outcome is fine, but
        // it must not claim the feature is missing.
        assert!(!stderr(&out).contains("--features live"));
    } else {
        assert!(!out.status.success());
        let text = stderr(&out);
        assert!(text.contains("--features live"), "{text}");
        assert!(
            text.contains("root") || text.contains("CAP_NET_RAW"),
            "{text}"
        );
    }
}

#[test]
fn devices_is_informative_without_the_live_feature() {
    let out = run(&["devices"]);
    if !cfg!(feature = "live") {
        // Listing nothing is the honest answer, and it should say why. This
        // is not an error: asking what is available is a fair question.
        assert!(out.status.success(), "{}", stderr(&out));
        assert!(stdout(&out).contains("--features live"), "{}", stdout(&out));
    }
}

#[test]
fn summary_of_a_pcapng_file_works_the_same() {
    let mut w = PcapngWriter::new();
    let iface = w.interface(1, 262_144);
    w.packet(
        iface,
        1_700_000_000_000_000,
        &ethernet(
            MAC_A,
            MAC_B,
            0x0800,
            &ipv4(
                Ipv4 {
                    protocol: 17,
                    ..Default::default()
                },
                &udp(40000, 53, &dns_query(1, "example.net", 1)),
            ),
        ),
    );
    let (_dir, path) = w.write_to_temp("one.pcapng");
    let out = run(&["summary", path.to_str().unwrap()]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("pcapng"), "{text}");
    assert!(text.contains("packets:  1"), "{text}");
}

#[test]
fn a_capture_with_no_packets_says_so_rather_than_opening_the_viewer() {
    // Without this, running the tool on an empty capture starts a TUI that
    // shows nothing and has to be quit.
    let w = PcapWriter::new(1);
    let (_dir, path) = w.write_to_temp("empty.pcap");
    let out = run(&[path.to_str().unwrap()]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("no packets"), "{}", stdout(&out));
}

#[test]
fn the_binary_exists_where_the_readme_says_it_does() {
    // A small guard on the documented build output path.
    let exe = Path::new(env!("CARGO_BIN_EXE_pcap-tui"));
    assert!(exe.exists());
    assert_eq!(exe.file_stem().unwrap().to_str().unwrap(), "pcap-tui");
}
