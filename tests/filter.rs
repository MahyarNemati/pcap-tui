//! Tests for the display filter and the statistics.
//!
//! The filter is the feature that makes a capture readable, so it is worth
//! testing that a term which cannot ever match says so: "no packets" and
//! "you made a typo" look identical on screen otherwise.

mod support;

use pcap_tui::app::{validate_filter, App};
use pcap_tui::pcap::Reader;
use support::*;

fn loaded() -> App {
    let w = mixed_capture();
    let mut reader = Reader::from_reader(Box::new(std::io::Cursor::new(w.bytes))).unwrap();
    let mut app = App::new("test".into(), "pcap".into());
    while let Some(p) = reader.next_packet().unwrap() {
        app.push(p);
    }
    app
}

fn visible(app: &App) -> Vec<u64> {
    app.visible_rows().map(|(_, r)| r.packet.number).collect()
}

#[test]
fn an_empty_filter_shows_everything() {
    let app = loaded();
    assert_eq!(app.len(), 6);
    assert_eq!(app.visible_len(), 6);
}

#[test]
fn filters_by_protocol_port_and_address() {
    let mut app = loaded();

    app.set_filter("proto:dns".into());
    assert_eq!(visible(&app), vec![3], "only the DNS query");

    app.set_filter("port:443".into());
    assert_eq!(visible(&app), vec![4], "only the TLS flow");

    app.set_filter("dst:8.8.8.8".into());
    assert_eq!(visible(&app), vec![5], "only the ping");

    app.set_filter("ip:10.0.0.2".into());
    assert_eq!(visible(&app), vec![1, 2], "both halves of the handshake");
}

#[test]
fn terms_are_combined_with_and() {
    let mut app = loaded();
    app.set_filter("tcp:1 port:80".into());
    assert_eq!(visible(&app), vec![1, 2]);
    app.set_filter("tcp:1 port:80 flag:syn".into());
    assert_eq!(visible(&app), vec![1, 2]);
    app.set_filter("tcp:1 port:80 flag:fin".into());
    assert!(visible(&app).is_empty());
}

#[test]
fn a_leading_bang_negates_a_term() {
    let mut app = loaded();
    app.set_filter("!proto:dns".into());
    assert_eq!(visible(&app), vec![1, 2, 4, 5, 6]);

    // Negation composes with the AND, which is what makes it useful: show
    // me everything except the noise.
    app.set_filter("!proto:dns !proto:arp".into());
    assert_eq!(visible(&app), vec![1, 2, 4, 5]);
}

#[test]
fn flags_are_matched_by_name_as_well_as_by_letter() {
    let mut app = loaded();
    app.set_filter("flag:ack".into());
    assert_eq!(visible(&app), vec![2, 4], "SYN-ACK and the TLS PSH-ACK");
    app.set_filter("flag:a".into());
    assert_eq!(
        visible(&app),
        vec![2, 4],
        "the single letter means the same"
    );
    app.set_filter("flag:syn".into());
    assert_eq!(visible(&app), vec![1, 2]);
}

#[test]
fn a_bare_term_is_a_substring_search_over_what_is_on_screen() {
    let mut app = loaded();
    app.set_filter("example.com".into());
    assert_eq!(
        visible(&app),
        vec![3, 4],
        "the DNS query and the TLS SNI host"
    );

    app.set_filter("ICMP".into());
    assert_eq!(visible(&app), vec![5], "matching is case-insensitive");
}

#[test]
fn length_predicates_use_the_original_length() {
    let mut app = loaded();
    app.set_filter("minlen:100".into());
    let big = visible(&app);
    assert!(
        big.contains(&4),
        "the TLS ClientHello is the largest packet"
    );
    app.set_filter("maxlen:60".into());
    assert!(!visible(&app).contains(&4));
}

#[test]
fn an_unknown_key_is_reported_rather_than_matching_nothing_in_silence() {
    // This is the whole point of validating: `prot:tcp` showing an empty
    // list is indistinguishable from a filter that is simply too narrow.
    let message = validate_filter("prot:tcp").expect("should be rejected");
    assert!(message.contains("prot"), "{message}");
    assert!(
        message.contains("proto"),
        "the message should list valid keys: {message}"
    );

    assert!(validate_filter("proto:tcp port:80 example.com").is_none());

    let mut app = loaded();
    app.set_filter("prot:tcp".into());
    assert!(
        app.filter_error.is_some(),
        "the app should surface the error"
    );
    app.set_filter("proto:tcp".into());
    assert!(app.filter_error.is_none());
}

#[test]
fn typing_a_filter_a_character_at_a_time_narrows_it() {
    // The UI applies the filter on every keystroke, so each prefix has to be
    // a valid filter in its own right.
    let mut app = loaded();
    for c in "proto:dns".chars() {
        app.push_filter_char(c);
    }
    assert_eq!(app.filter(), "proto:dns");
    assert_eq!(visible(&app), vec![3]);

    app.pop_filter_char();
    assert_eq!(app.filter(), "proto:dn");
    assert_eq!(
        visible(&app),
        vec![3],
        "a prefix of the protocol still matches"
    );

    app.clear_filter();
    assert_eq!(app.visible_len(), 6);
}

#[test]
fn the_cursor_stays_within_the_filtered_list() {
    // Filtering down to fewer rows than the cursor index would otherwise
    // index out of bounds, or show the wrong packet in the detail pane.
    let mut app = loaded();
    app.last();
    assert_eq!(app.cursor(), 5);
    app.set_filter("proto:dns".into());
    assert_eq!(app.visible_len(), 1);
    assert_eq!(app.cursor(), 0);
    assert_eq!(app.selected().expect("a row").packet.number, 3);
}

#[test]
fn navigation_stops_at_both_ends() {
    let mut app = loaded();
    app.first();
    app.previous();
    assert_eq!(app.cursor(), 0, "up at the top stays at the top");
    app.last();
    app.next();
    assert_eq!(app.cursor(), 5, "down at the bottom stays at the bottom");
    app.page_up(100);
    assert_eq!(app.cursor(), 0);
    app.page_down(100);
    assert_eq!(app.cursor(), 5);
}

#[test]
fn navigating_an_empty_filtered_list_does_not_panic() {
    let mut app = loaded();
    app.set_filter("port:9999".into());
    assert_eq!(app.visible_len(), 0);
    app.next();
    app.previous();
    app.page_down(10);
    app.page_up(10);
    app.first();
    app.last();
    assert!(app.selected().is_none());
}

#[test]
fn protocol_stats_count_packets_and_bytes() {
    let app = loaded();
    let stats = app.protocol_stats();
    let total: usize = stats.iter().map(|s| s.1).sum();
    assert_eq!(total, 6, "every packet is counted exactly once");

    let names: Vec<&str> = stats.iter().map(|s| s.0.as_str()).collect();
    assert!(names.contains(&"DNS"), "{names:?}");
    assert!(names.contains(&"TLS"), "{names:?}");
    assert!(names.contains(&"ARP"), "{names:?}");

    // Sorted busiest first.
    for pair in stats.windows(2) {
        assert!(pair[0].1 >= pair[1].1, "not sorted: {stats:?}");
    }
}

#[test]
fn both_directions_of_a_conversation_are_one_row() {
    // A capture of a TCP handshake has packets in both directions. Counting
    // them as two conversations makes the busiest-talkers list useless.
    let app = loaded();
    let flows = app.top_flows(10);
    let handshake: Vec<_> = flows
        .iter()
        .filter(|(f, _, _)| f.contains("10.0.0.1:50000") && f.contains("10.0.0.2:80"))
        .collect();
    assert_eq!(handshake.len(), 1, "expected one row, got {flows:#?}");
    assert_eq!(handshake[0].1, 2, "both packets counted");
    assert!(
        handshake[0].0.contains('⇄'),
        "direction should be shown as bidirectional"
    );
}

#[test]
fn top_flows_respects_its_limit() {
    let app = loaded();
    assert!(app.top_flows(2).len() <= 2);
    assert!(app.top_flows(100).len() <= app.len());
}

#[test]
fn summary_reports_bytes_and_the_time_span() {
    let app = loaded();
    let (bytes, span) = app.summary();
    assert!(bytes > 0);
    let (first, last) = span.expect("a span");
    let seconds = last.duration_since(first).unwrap().as_secs_f64();
    assert!(
        (seconds - 3.9).abs() < 1e-6,
        "the fixture spans 3.9 seconds, got {seconds}"
    );
}

#[test]
fn an_empty_capture_has_no_span_and_no_stats() {
    let app = App::new("empty".into(), "pcap".into());
    assert!(app.is_empty());
    let (bytes, span) = app.summary();
    assert_eq!(bytes, 0);
    assert!(span.is_none());
    assert!(app.protocol_stats().is_empty());
    assert!(app.top_flows(10).is_empty());
}

#[test]
fn an_address_term_does_not_match_a_longer_address_by_accident() {
    // `ip:10.0.0.2` matching 10.0.0.254 is the kind of silent over-match
    // that makes a filter untrustworthy.
    let mut app = loaded();
    app.set_filter("ip:10.0.0.5".into());
    assert!(visible(&app).is_empty());

    app.set_filter("ip:10.0.0.1".into());
    assert_eq!(visible(&app).len(), 6, "every packet involves 10.0.0.1");

    // The ARP packet in the fixture targets 10.0.0.254.
    app.set_filter("dst:10.0.0.25".into());
    assert!(
        visible(&app).is_empty(),
        "a prefix of an address is not an address"
    );
    app.set_filter("dst:10.0.0.254".into());
    assert_eq!(visible(&app), vec![6]);
}

#[test]
fn an_address_term_accepts_a_cidr_network() {
    let mut app = loaded();
    app.set_filter("dst:10.0.0.0/24".into());
    let inside = visible(&app);
    assert!(inside.contains(&1), "{inside:?}");
    assert!(
        !inside.contains(&5),
        "8.8.8.8 is outside 10.0.0.0/24: {inside:?}"
    );

    app.set_filter("dst:8.8.8.0/24".into());
    assert_eq!(visible(&app), vec![5]);

    // A prefix that is not on a byte boundary still has to work.
    app.set_filter("dst:8.8.8.8/31".into());
    assert_eq!(visible(&app), vec![5]);
    app.set_filter("dst:8.8.8.10/31".into());
    assert!(visible(&app).is_empty());

    // /0 matches every address of that family.
    app.set_filter("src:0.0.0.0/0".into());
    assert_eq!(visible(&app).len(), 6);
}

#[test]
fn a_trailing_separator_makes_an_address_term_a_prefix() {
    let mut app = loaded();
    app.set_filter("dst:10.0.".into());
    let inside = visible(&app);
    assert!(inside.contains(&1), "{inside:?}");
    assert!(!inside.contains(&5), "{inside:?}");
}

#[test]
fn a_nonsense_address_term_matches_nothing_rather_than_everything() {
    let mut app = loaded();
    for term in ["ip:zzz", "ip:10.0.0.0/99", "ip:10.0.0.0/abc", "ip:/24"] {
        app.set_filter(term.into());
        assert!(visible(&app).is_empty(), "{term} should match nothing");
    }
}

#[test]
fn an_ipv4_term_never_matches_an_ipv6_address() {
    // Mixing the families would make `src:0.0.0.0/0` a match-everything
    // filter even on an IPv6 capture.
    let mut w = PcapWriter::new(1);
    w.push(
        1,
        0,
        &ethernet(
            MAC_A,
            MAC_B,
            0x86dd,
            &ipv6(
                [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
                6,
                &tcp(Tcp::default(), &[]),
            ),
        ),
    );
    let mut reader = Reader::from_reader(Box::new(std::io::Cursor::new(w.bytes))).unwrap();
    let mut app = App::new("v6".into(), "pcap".into());
    while let Some(p) = reader.next_packet().unwrap() {
        app.push(p);
    }

    app.set_filter("src:0.0.0.0/0".into());
    assert!(
        visible(&app).is_empty(),
        "a v4 network must not match a v6 address"
    );
    app.set_filter("src:2001:db8::/32".into());
    assert_eq!(visible(&app).len(), 1);
    app.set_filter("src:2001:db8::1".into());
    assert_eq!(visible(&app).len(), 1);
    app.set_filter("src:2001:db9::/32".into());
    assert!(visible(&app).is_empty());
}
