//! Rendering. Pure presentation: it reads App and draws, and holds no state
//! of its own.

use std::time::{SystemTime, UNIX_EPOCH};

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row as TableRow, Table, Wrap};
use ratatui::Frame;

use crate::app::{App, Pane};
use crate::decode;

const HEADER_STYLE: Style = Style::new().fg(Color::Black).bg(Color::Cyan);
const SELECTED_STYLE: Style = Style::new().fg(Color::Black).bg(Color::LightCyan);

pub fn draw(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),  // title
            Constraint::Min(8),     // packet list
            Constraint::Length(14), // detail
            Constraint::Length(1),  // status / filter
        ])
        .split(f.area());

    draw_title(f, chunks[0], app);
    draw_list(f, chunks[1], app);
    draw_detail(f, chunks[2], app);
    draw_status(f, chunks[3], app);

    if app.show_help {
        draw_help(f, f.area());
    }
}

fn draw_title(f: &mut Frame, area: Rect, app: &App) {
    let shown = if app.filter().is_empty() {
        format!("{} packets", app.len())
    } else {
        format!("{} of {} packets", app.visible_len(), app.len())
    };
    let line = Line::from(vec![
        Span::styled(
            " pcap-tui ",
            Style::new()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!(" {} ", app.source)),
        Span::styled(
            format!("[{}] ", app.format),
            Style::new().fg(Color::DarkGray),
        ),
        Span::styled(shown, Style::new().fg(Color::Gray)),
        Span::styled("   ? for help", Style::new().fg(Color::DarkGray)),
    ]);
    f.render_widget(Paragraph::new(line), area);
}

fn draw_list(f: &mut Frame, area: Rect, app: &App) {
    let header = TableRow::new(vec![
        Cell::from("#"),
        Cell::from("time"),
        Cell::from("source → destination"),
        Cell::from("proto"),
        Cell::from("len"),
        Cell::from("info"),
    ])
    .style(HEADER_STYLE);

    // Render only what fits. A capture can hold millions of packets, and
    // building a widget per packet would make scrolling unusable.
    let height = area.height.saturating_sub(3) as usize;
    let start = app
        .cursor()
        .saturating_sub(height / 2)
        .min(app.visible_len().saturating_sub(height));

    let rows: Vec<TableRow> = app
        .visible_rows()
        .skip(start)
        .take(height)
        .enumerate()
        .map(|(offset, (_, row))| {
            let d = &row.decoded;
            let selected = start + offset == app.cursor();
            let mut style = protocol_style(&d.top_protocol);
            if selected {
                style = SELECTED_STYLE.add_modifier(Modifier::BOLD);
            }
            let len = if row.packet.truncated() {
                // Flagging truncation matters: the decoder was working with
                // an incomplete header.
                format!("{}*", row.packet.original_len)
            } else {
                row.packet.original_len.to_string()
            };
            TableRow::new(vec![
                Cell::from(row.packet.number.to_string()),
                Cell::from(format_time(row.packet.timestamp)),
                Cell::from(d.flow()),
                Cell::from(d.top_protocol.clone()),
                Cell::from(len),
                Cell::from(d.info.clone()),
            ])
            .style(style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(7),
            Constraint::Length(15),
            Constraint::Length(46),
            Constraint::Length(10),
            Constraint::Length(7),
            Constraint::Min(20),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(if app.pane == Pane::List {
                " packets (focused) "
            } else {
                " packets "
            })
            .border_style(focus_style(app.pane == Pane::List)),
    );

    f.render_widget(table, area);
}

fn draw_detail(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(if app.pane == Pane::Detail {
            " detail (focused) "
        } else {
            " detail "
        })
        .border_style(focus_style(app.pane == Pane::Detail));

    let Some(row) = app.selected() else {
        let msg = if app.is_empty() {
            "No packets."
        } else {
            "No packets match the filter."
        };
        f.render_widget(Paragraph::new(msg).block(block), area);
        return;
    };

    let d = &row.decoded;
    let mut lines: Vec<Line> = Vec::new();

    lines.push(field(
        "frame",
        format!(
            "#{}  {}  {} bytes on the wire, {} captured{}",
            row.packet.number,
            format_time_full(row.packet.timestamp),
            row.packet.original_len,
            row.packet.data.len(),
            if row.packet.truncated() {
                "  (TRUNCATED by snaplen)"
            } else {
                ""
            }
        ),
    ));

    if let (Some(src), Some(dst)) = (d.src_mac, d.dst_mac) {
        let eth = d
            .ethertype
            .map(|t| format!("  ethertype 0x{t:04x}"))
            .unwrap_or_default();
        lines.push(field("ethernet", format!("{src} → {dst}{eth}")));
    }

    if d.src_ip.is_some() {
        let mut ip = format!(
            "{} → {}",
            d.src_ip.map(|i| i.to_string()).unwrap_or_default(),
            d.dst_ip.map(|i| i.to_string()).unwrap_or_default()
        );
        if let Some(ttl) = d.ttl {
            ip.push_str(&format!("  ttl/hop-limit {ttl}"));
        }
        if d.fragmented {
            ip.push_str(&format!("  FRAGMENT offset {}", d.fragment_offset * 8));
        }
        lines.push(field("ip", ip));
    }

    if let Some(proto) = d.protocol {
        let mut t = proto.name();
        if let (Some(sp), Some(dp)) = (d.src_port, d.dst_port) {
            t.push_str(&format!("  {sp} → {dp}"));
        }
        if let Some(flags) = d.tcp_flags {
            t.push_str(&format!("  flags [{flags}]"));
        }
        if let Some(seq) = d.seq {
            t.push_str(&format!("  seq {seq}"));
        }
        if let Some(ack) = d.ack {
            t.push_str(&format!("  ack {ack}"));
        }
        if let Some(win) = d.window {
            t.push_str(&format!("  win {win}"));
        }
        lines.push(field("transport", t));
    }

    lines.push(field(
        &d.top_protocol.to_lowercase(),
        format!("{}  ({} payload bytes)", d.info, d.payload_len),
    ));
    lines.push(Line::raw(""));

    // Saying where the payload starts turns the hex dump from a wall of
    // bytes into something you can read against the headers above it.
    lines.push(Line::styled(
        if d.payload_len == 0 {
            format!("{} captured bytes, no payload", row.packet.data.len())
        } else {
            format!(
                "{} captured bytes; payload at offset 0x{:04x}",
                row.packet.data.len(),
                d.payload_offset
            )
        },
        Style::new().fg(Color::DarkGray),
    ));

    // The hex dump, scrollable.
    for line in decode::hex_dump(&row.packet.data, 512) {
        lines.push(Line::styled(line, Style::new().fg(Color::DarkGray)));
    }

    let paragraph = Paragraph::new(lines)
        .block(block)
        .scroll((app.detail_scroll, 0))
        .wrap(Wrap { trim: false });
    f.render_widget(paragraph, area);
}

fn field(label: &str, value: String) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("{label:>10}  "),
            Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ),
        Span::raw(value),
    ])
}

fn draw_status(f: &mut Frame, area: Rect, app: &App) {
    if app.editing_filter {
        let line = Line::from(vec![
            Span::styled(" filter ", Style::new().fg(Color::Black).bg(Color::Yellow)),
            Span::raw(format!(" {}", app.filter())),
            Span::styled("█", Style::new().fg(Color::Yellow)),
        ]);
        f.render_widget(Paragraph::new(line), area);
        return;
    }

    // A filter typo must be distinguishable from "nothing matched".
    if let Some(err) = &app.filter_error {
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(
                    " filter error ",
                    Style::new().fg(Color::Black).bg(Color::Red),
                ),
                Span::raw(format!(" {err}")),
            ])),
            area,
        );
        return;
    }

    // Where the cursor is, in the filtered list and in the capture. Without
    // it there is no way to tell a short list from the top of a long one.
    let position = if app.is_empty() {
        " no packets ".to_string()
    } else if app.visible_len() == 0 {
        format!(" 0 of {} shown ", app.len())
    } else if app.visible_len() == app.len() {
        format!(" packet {} of {} ", app.cursor() + 1, app.len())
    } else {
        format!(
            " packet {} of {} shown, {} captured ",
            app.cursor() + 1,
            app.visible_len(),
            app.len()
        )
    };
    let mut spans = vec![
        Span::styled(position, Style::new().fg(Color::Black).bg(Color::Cyan)),
        Span::styled(
            "  j/k move  Tab pane  / filter  q quit ",
            Style::new().fg(Color::DarkGray),
        ),
    ];
    if !app.filter().is_empty() {
        spans.push(Span::styled(
            format!(" filter: {} ", app.filter()),
            Style::new().fg(Color::Black).bg(Color::Yellow),
        ));
    }
    if app.follow {
        spans.push(Span::styled(
            " FOLLOW ",
            Style::new().fg(Color::Black).bg(Color::Green),
        ));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_help(f: &mut Frame, area: Rect) {
    let width = 62.min(area.width.saturating_sub(4));
    let height = 20.min(area.height.saturating_sub(4));
    let popup = Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    };

    let text = vec![
        Line::styled(
            "navigation",
            Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ),
        Line::raw("  j / ↓        next packet"),
        Line::raw("  k / ↑        previous packet"),
        Line::raw("  Ctrl-d / -u  page down / up"),
        Line::raw("  g / G        first / last"),
        Line::raw("  Tab          switch pane"),
        Line::raw("  J / K        scroll the detail pane"),
        Line::raw(""),
        Line::styled(
            "filtering",
            Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ),
        Line::raw("  /            edit the filter   Esc to cancel"),
        Line::raw("  c            clear the filter"),
        Line::raw("  terms are ANDed; prefix ! to negate"),
        Line::raw("  ip: src: dst: port: sport: dport:"),
        Line::raw("  proto: tcp: udp: flag: minlen: maxlen:"),
        Line::raw("  anything else is a substring search"),
        Line::raw(""),
        Line::styled(
            "  example: tcp: port:443 !flag:f",
            Style::new().fg(Color::Green),
        ),
        Line::raw(""),
        Line::raw("  ? close help      q quit"),
    ];

    f.render_widget(Clear, popup);
    f.render_widget(
        Paragraph::new(text).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" help ")
                .border_style(Style::new().fg(Color::Cyan)),
        ),
        popup,
    );
}

fn focus_style(focused: bool) -> Style {
    if focused {
        Style::new().fg(Color::Cyan)
    } else {
        Style::new().fg(Color::DarkGray)
    }
}

/// Colour by protocol, which is most of what makes a packet list scannable.
fn protocol_style(proto: &str) -> Style {
    let colour = match proto {
        "TCP" => Color::Blue,
        "UDP" => Color::Magenta,
        "DNS" | "MDNS" => Color::Green,
        "TLS" | "HTTPS" => Color::LightGreen,
        "HTTP" | "HTTP-ALT" => Color::Yellow,
        "ICMP" | "ICMPv6" => Color::LightRed,
        "ARP" => Color::LightMagenta,
        _ => Color::Gray,
    };
    Style::new().fg(colour)
}

/// Seconds-and-microseconds, which is what matters when reading a capture.
pub fn format_time(ts: SystemTime) -> String {
    match ts.duration_since(UNIX_EPOCH) {
        Ok(d) => {
            let secs = d.as_secs();
            format!(
                "{:02}:{:02}:{:02}.{:06}",
                (secs / 3600) % 24,
                (secs / 60) % 60,
                secs % 60,
                d.subsec_micros()
            )
        }
        Err(_) => "?".into(),
    }
}

/// format_time_full includes the date.
pub fn format_time_full(ts: SystemTime) -> String {
    match ts.duration_since(UNIX_EPOCH) {
        Ok(d) => {
            // A date conversion without a calendar crate: days since epoch
            // via the civil-from-days algorithm. Pulling in chrono for one
            // timestamp format would be the only dependency used once.
            let secs = d.as_secs();
            let days = (secs / 86_400) as i64;
            let (y, m, dd) = civil_from_days(days);
            format!("{y:04}-{m:02}-{dd:02} {}", format_time(ts))
        }
        Err(_) => "?".into(),
    }
}

/// civil_from_days is Howard Hinnant's algorithm: days since 1970-01-01 to a
/// calendar date, with no table and no leap-year special cases.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}
