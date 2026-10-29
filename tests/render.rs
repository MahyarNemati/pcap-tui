//! Rendering tests.
//!
//! A TUI is still worth testing: the interesting failures are a pane that
//! disappears at a small terminal size, a row that is silently cut off, and
//! a selection that renders the wrong packet. Rendering into an in-memory
//! buffer catches all three without a terminal.

mod support;

use pcap_tui::app::{App, Pane};
use pcap_tui::pcap::Reader;
use pcap_tui::ui;
use ratatui::backend::TestBackend;
use ratatui::Terminal;
use support::*;

fn loaded() -> App {
    let w = mixed_capture();
    let mut reader = Reader::from_reader(Box::new(std::io::Cursor::new(w.bytes))).unwrap();
    let mut app = App::new("mixed.pcap".into(), "pcap, Ethernet".into());
    while let Some(p) = reader.next_packet().unwrap() {
        app.push(p);
    }
    app.follow = false;
    app.first();
    app
}

/// render draws the app and returns the screen as text, one line per row.
fn render(app: &App, width: u16, height: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("terminal");
    terminal.draw(|f| ui::draw(f, app)).expect("draw");
    let buffer = terminal.backend().buffer().clone();
    let mut out = String::new();
    for y in 0..buffer.area.height {
        for x in 0..buffer.area.width {
            out.push_str(buffer[(x, y)].symbol());
        }
        out.push('\n');
    }
    out
}

#[test]
fn the_title_names_the_source_and_the_format() {
    let app = loaded();
    let screen = render(&app, 120, 30);
    assert!(screen.contains("mixed.pcap"), "{screen}");
    assert!(screen.contains("Ethernet"), "{screen}");
}

#[test]
fn the_list_shows_every_packet_when_there_is_room() {
    let app = loaded();
    let screen = render(&app, 120, 40);
    for host in ["10.0.0.2", "8.8.8.8", "93.184.216.34"] {
        assert!(screen.contains(host), "{host} missing from:\n{screen}");
    }
    for proto in ["DNS", "TLS", "ICMP", "ARP"] {
        assert!(screen.contains(proto), "{proto} missing from:\n{screen}");
    }
}

#[test]
fn the_detail_pane_follows_the_selection() {
    let mut app = loaded();
    app.set_filter("proto:dns".into());
    let screen = render(&app, 120, 40);
    assert!(
        screen.contains("example.com"),
        "the selected packet's detail should be shown:\n{screen}"
    );

    app.clear_filter();
    app.first();
    let screen = render(&app, 120, 40);
    assert!(
        screen.contains("seq="),
        "the first packet is TCP, so its detail should show a sequence number:\n{screen}"
    );
}

#[test]
fn the_focused_pane_is_marked() {
    let mut app = loaded();
    let screen = render(&app, 120, 30);
    assert!(screen.contains("focused"), "{screen}");

    app.pane = Pane::Detail;
    let screen = render(&app, 120, 30);
    assert!(screen.contains("detail (focused)"), "{screen}");
}

#[test]
fn the_filter_and_its_error_are_visible() {
    let mut app = loaded();
    app.set_filter("prot:tcp".into());
    let screen = render(&app, 120, 30);
    assert!(
        screen.contains("unknown filter key") || screen.contains("prot"),
        "a filter typo must be visible on screen:\n{screen}"
    );
}

#[test]
fn the_status_line_reports_the_position_in_the_capture() {
    // Without a position there is no way to tell the top of a long list from
    // a short one, and no way to see how much a filter hid.
    let mut app = loaded();
    app.first();
    let screen = render(&app, 120, 30);
    assert!(screen.contains("packet 1 of 6"), "{screen}");

    app.last();
    let screen = render(&app, 120, 30);
    assert!(screen.contains("packet 6 of 6"), "{screen}");

    app.set_filter("proto:dns".into());
    let screen = render(&app, 120, 30);
    assert!(
        screen.contains("packet 1 of 1 shown, 6 captured"),
        "a filter should say how much it hid:\n{screen}"
    );

    app.set_filter("port:9999".into());
    let screen = render(&app, 120, 30);
    assert!(screen.contains("0 of 6 shown"), "{screen}");

    let empty = App::new("empty".into(), "pcap".into());
    let screen = render(&empty, 120, 30);
    assert!(screen.contains("no packets"), "{screen}");
}

#[test]
fn the_help_overlay_lists_the_keys() {
    let mut app = loaded();
    app.show_help = true;
    let screen = render(&app, 120, 40);
    for key in ["quit", "filter"] {
        assert!(
            screen.to_lowercase().contains(key),
            "{key} missing:\n{screen}"
        );
    }
}

#[test]
fn renders_at_a_small_terminal_size_without_panicking() {
    // Layout arithmetic that assumes room for every pane panics on a short
    // terminal, which is exactly where a user will first open the tool.
    let app = loaded();
    for (w, h) in [(20u16, 5u16), (40, 8), (1, 1), (200, 60), (80, 3)] {
        let screen = render(&app, w, h);
        assert_eq!(
            screen.lines().count(),
            h as usize,
            "wrong number of rows at {w}x{h}"
        );
    }
}

#[test]
fn renders_an_empty_capture_without_panicking() {
    let app = App::new("empty.pcap".into(), "pcap".into());
    let screen = render(&app, 80, 24);
    assert!(screen.contains("empty.pcap"), "{screen}");
}

#[test]
fn renders_an_empty_filter_result_without_panicking() {
    let mut app = loaded();
    app.set_filter("port:9999".into());
    assert_eq!(app.visible_len(), 0);
    let _ = render(&app, 100, 30);
}

#[test]
fn scrolling_the_detail_pane_past_the_end_is_harmless() {
    let mut app = loaded();
    app.detail_scroll = u16::MAX;
    let _ = render(&app, 100, 30);
}

#[test]
fn the_list_scrolls_to_keep_the_selection_visible() {
    // With more packets than rows, the selected packet must stay on screen;
    // a list that scrolls only when the cursor leaves the buffer shows the
    // wrong thing after a jump to the end.
    let mut w = PcapWriter::new(1);
    for i in 0..200u32 {
        let p = ethernet(
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
                        src_port: 40000 + i as u16,
                        ..Default::default()
                    },
                    &[],
                ),
            ),
        );
        w.push(1_700_000_000 + i, 0, &p);
    }
    let mut reader = Reader::from_reader(Box::new(std::io::Cursor::new(w.bytes))).unwrap();
    let mut app = App::new("many.pcap".into(), "pcap".into());
    while let Some(p) = reader.next_packet().unwrap() {
        app.push(p);
    }
    app.follow = false;

    app.first();
    let screen = render(&app, 120, 20);
    assert!(
        screen.contains(":40000"),
        "the first packet should be shown:\n{screen}"
    );

    app.last();
    let screen = render(&app, 120, 20);
    assert!(
        screen.contains(":40199"),
        "the last packet should be shown after jumping to the end:\n{screen}"
    );
    assert!(
        !screen.contains(":40000"),
        "the top of the list should have scrolled away:\n{screen}"
    );
}
