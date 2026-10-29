//! Application state: the packet list, filters and selection.
//!
//! Kept entirely separate from rendering and from input handling, so the
//! interesting logic -- filtering, selection, statistics -- is testable
//! without a terminal. A TUI whose state is tangled into its draw calls can
//! only be tested by screen-scraping, which nobody does, so it ends up
//! untested.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::SystemTime;

use crate::decode::{self, Decoded, Protocol, TcpFlags};
use crate::pcap::Packet;

/// A packet plus its decoded form.
pub struct Row {
    pub packet: Packet,
    pub decoded: Decoded,
}

/// Which pane has focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pane {
    List,
    Detail,
}

/// Application state.
pub struct App {
    rows: Vec<Row>,
    /// Indices into rows that match the current filter.
    visible: Vec<usize>,
    /// Position within `visible`, not within `rows`.
    cursor: usize,
    filter: String,
    /// filter_error holds the reason a filter matched nothing structurally,
    /// so a typo is distinguishable from "no matching packets".
    pub filter_error: Option<String>,
    pub editing_filter: bool,
    pub pane: Pane,
    pub detail_scroll: u16,
    pub show_help: bool,
    pub source: String,
    pub format: String,
    /// follow keeps the cursor on the newest packet during live capture.
    pub follow: bool,
}

impl App {
    pub fn new(source: String, format: String) -> Self {
        App {
            rows: Vec::new(),
            visible: Vec::new(),
            cursor: 0,
            filter: String::new(),
            filter_error: None,
            editing_filter: false,
            pane: Pane::List,
            detail_scroll: 0,
            show_help: false,
            source,
            format,
            follow: true,
        }
    }

    /// Adds a packet, decoding it immediately.
    pub fn push(&mut self, packet: Packet) {
        let decoded = decode::decode(&packet);
        let index = self.rows.len();
        self.rows.push(Row { packet, decoded });

        if self.matches(index) {
            self.visible.push(index);
            if self.follow {
                self.cursor = self.visible.len().saturating_sub(1);
            }
        }
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub fn visible_len(&self) -> usize {
        self.visible.len()
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    pub fn filter(&self) -> &str {
        &self.filter
    }

    /// The rows currently visible, in order.
    pub fn visible_rows(&self) -> impl Iterator<Item = (usize, &Row)> {
        self.visible.iter().map(|&i| (i, &self.rows[i]))
    }

    pub fn selected(&self) -> Option<&Row> {
        self.visible.get(self.cursor).map(|&i| &self.rows[i])
    }

    // ---------- navigation ----------

    pub fn next(&mut self) {
        if self.cursor + 1 < self.visible.len() {
            self.cursor += 1;
            self.detail_scroll = 0;
        }
        // Moving off the end re-enables follow; moving away from it disables.
        self.follow = self.cursor + 1 >= self.visible.len();
    }

    pub fn previous(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
        self.detail_scroll = 0;
        self.follow = false;
    }

    pub fn page_down(&mut self, page: usize) {
        self.cursor = (self.cursor + page).min(self.visible.len().saturating_sub(1));
        self.detail_scroll = 0;
        self.follow = self.cursor + 1 >= self.visible.len();
    }

    pub fn page_up(&mut self, page: usize) {
        self.cursor = self.cursor.saturating_sub(page);
        self.detail_scroll = 0;
        self.follow = false;
    }

    pub fn first(&mut self) {
        self.cursor = 0;
        self.detail_scroll = 0;
        self.follow = false;
    }

    pub fn last(&mut self) {
        self.cursor = self.visible.len().saturating_sub(1);
        self.detail_scroll = 0;
        self.follow = true;
    }

    // ---------- filtering ----------

    /// Sets the filter and reapplies it.
    pub fn set_filter(&mut self, filter: String) {
        self.filter = filter;
        self.reapply();
    }

    pub fn push_filter_char(&mut self, c: char) {
        self.filter.push(c);
        self.reapply();
    }

    pub fn pop_filter_char(&mut self) {
        self.filter.pop();
        self.reapply();
    }

    pub fn clear_filter(&mut self) {
        self.filter.clear();
        self.reapply();
    }

    fn reapply(&mut self) {
        self.filter_error = validate_filter(&self.filter);
        self.visible = (0..self.rows.len()).filter(|&i| self.matches(i)).collect();
        // Clamp rather than reset: keeping the cursor near where it was is
        // less disorienting than jumping to the top on every keystroke.
        self.cursor = self.cursor.min(self.visible.len().saturating_sub(1));
    }

    /// Reports whether row `i` passes the filter.
    ///
    /// The filter language is deliberately tiny: space-separated terms, all of
    /// which must match (AND), each either a `key:value` predicate or a
    /// substring searched across the summary line. A full BPF or Wireshark
    /// display-filter parser is a large project and would be the whole of this
    /// one; this covers what a person actually types while reading a capture.
    fn matches(&self, i: usize) -> bool {
        if self.filter.trim().is_empty() {
            return true;
        }
        let row = &self.rows[i];
        self.filter
            .split_whitespace()
            .all(|term| term_matches(term, row))
    }

    // ---------- statistics ----------

    /// Counts packets and bytes per protocol, for the summary command.
    pub fn protocol_stats(&self) -> Vec<(String, usize, u64)> {
        let mut counts: BTreeMap<String, (usize, u64)> = BTreeMap::new();
        for row in &self.rows {
            let entry = counts
                .entry(row.decoded.top_protocol.clone())
                .or_insert((0, 0));
            entry.0 += 1;
            entry.1 += row.packet.original_len as u64;
        }
        let mut out: Vec<_> = counts
            .into_iter()
            .map(|(k, (n, bytes))| (k, n, bytes))
            .collect();
        // Busiest first: that is the question being asked.
        out.sort_by_key(|e| std::cmp::Reverse(e.1));
        out
    }

    /// The busiest conversations, by packet count.
    pub fn top_flows(&self, limit: usize) -> Vec<(String, usize, u64)> {
        let mut counts: BTreeMap<String, (usize, u64)> = BTreeMap::new();
        for row in &self.rows {
            // Normalise direction so a conversation is one row, not two.
            let key = canonical_flow(&row.decoded);
            let entry = counts.entry(key).or_insert((0, 0));
            entry.0 += 1;
            entry.1 += row.packet.original_len as u64;
        }
        let mut out: Vec<_> = counts
            .into_iter()
            .map(|(k, (n, bytes))| (k, n, bytes))
            .collect();
        // Descending by packet count, so the busiest comes first.
        out.sort_by_key(|e| std::cmp::Reverse(e.1));
        out.truncate(limit);
        out
    }

    /// Total captured bytes and the capture's time span.
    pub fn summary(&self) -> (u64, Option<(SystemTime, SystemTime)>) {
        let bytes = self.rows.iter().map(|r| r.packet.original_len as u64).sum();
        let span = match (self.rows.first(), self.rows.last()) {
            (Some(a), Some(b)) => Some((a.packet.timestamp, b.packet.timestamp)),
            _ => None,
        };
        (bytes, span)
    }
}

/// canonical_flow orders the endpoints so both directions of a conversation
/// map to the same key.
fn canonical_flow(d: &Decoded) -> String {
    let a = match (d.src_ip, d.src_port) {
        (Some(ip), Some(p)) => format!("{ip}|{p}"),
        (Some(ip), None) => ip.to_string(),
        _ => "?".into(),
    };
    let b = match (d.dst_ip, d.dst_port) {
        (Some(ip), Some(p)) => format!("{ip}|{p}"),
        (Some(ip), None) => ip.to_string(),
        _ => "?".into(),
    };
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    format!("{} ⇄ {}", lo.replace('|', ":"), hi.replace('|', ":"))
}

/// validate_filter returns a message for a term that cannot ever match, so a
/// typo like `prot:tcp` is distinguishable from a filter that simply found
/// nothing.
pub fn validate_filter(filter: &str) -> Option<String> {
    const KEYS: &[&str] = &[
        "ip", "src", "dst", "port", "sport", "dport", "proto", "tcp", "udp", "len", "minlen",
        "maxlen", "flag",
    ];
    for term in filter.split_whitespace() {
        if let Some((key, _)) = term.split_once(':') {
            if !KEYS.contains(&key) {
                return Some(format!(
                    "unknown filter key {key:?}; try {}",
                    KEYS.join(", ")
                ));
            }
        }
    }
    None
}

fn term_matches(term: &str, row: &Row) -> bool {
    let d = &row.decoded;

    // Negation with a leading '!'.
    if let Some(rest) = term.strip_prefix('!') {
        return !term_matches(rest, row);
    }

    let Some((key, value)) = term.split_once(':') else {
        // A bare term is a case-insensitive substring search across the
        // things a person can see on screen.
        let needle = term.to_lowercase();
        let haystack = format!(
            "{} {} {} {}",
            d.flow(),
            d.top_protocol,
            d.info,
            d.protocol.map(|p| p.name()).unwrap_or_default()
        )
        .to_lowercase();
        return haystack.contains(&needle);
    };

    let v = value.to_lowercase();
    match key {
        "ip" => address_matches(d.src_ip, &v) || address_matches(d.dst_ip, &v),
        "src" => address_matches(d.src_ip, &v),
        "dst" => address_matches(d.dst_ip, &v),
        "port" => port_eq(d.src_port, &v) || port_eq(d.dst_port, &v),
        "sport" => port_eq(d.src_port, &v),
        "dport" => port_eq(d.dst_port, &v),
        "proto" => {
            d.top_protocol.to_lowercase().contains(&v)
                || d.protocol
                    .map(|p| p.name().to_lowercase() == v)
                    .unwrap_or(false)
        }
        "tcp" => matches!(d.protocol, Some(Protocol::Tcp)),
        "udp" => matches!(d.protocol, Some(Protocol::Udp)),
        "minlen" => v
            .parse::<u32>()
            .map(|n| row.packet.original_len >= n)
            .unwrap_or(false),
        "maxlen" => v
            .parse::<u32>()
            .map(|n| row.packet.original_len <= n)
            .unwrap_or(false),
        "len" => v
            .parse::<u32>()
            .map(|n| row.packet.original_len == n)
            .unwrap_or(false),
        // Flags are matched by name, not by the rendered string: the
        // rendered form uses '.' for ACK, so `flag:ack` would otherwise fail
        // while `flag:.` worked, which is the wrong way round.
        "flag" => d.tcp_flags.map(|f| flag_set(&f, &v)).unwrap_or(false),
        _ => false,
    }
}

/// flag_set reports whether a named TCP flag is set. Both the full name and
/// tcpdump's single character are accepted, since both are things people
/// have in their fingers.
fn flag_set(f: &TcpFlags, name: &str) -> bool {
    match name {
        "fin" | "f" => f.fin,
        "syn" | "s" => f.syn,
        "rst" | "r" => f.rst,
        "psh" | "push" | "p" => f.psh,
        "ack" | "a" | "." => f.ack,
        "urg" | "u" => f.urg,
        "ece" | "e" => f.ece,
        "cwr" | "w" => f.cwr,
        _ => false,
    }
}

/// address_matches tests an endpoint against an address term.
///
/// Three forms, in order of how often they are wanted:
///
/// * `10.0.0.5` or `2001:db8::1` -- an exact address.
/// * `10.0.0.0/24` -- a network, which is what you actually want when
///   looking at a subnet.
/// * `10.0.` or `2001:db8:` -- a textual prefix, for when you cannot
///   remember the mask. The trailing separator is required, because without
///   it `10.0.0.2` would also match `10.0.0.254`, and a filter that silently
///   matches more than it was asked to is worse than one that matches
///   nothing.
fn address_matches(ip: Option<IpAddr>, term: &str) -> bool {
    let Some(ip) = ip else { return false };

    if let Some((network, bits)) = term.split_once('/') {
        return match (network.parse::<IpAddr>(), bits.parse::<u8>()) {
            (Ok(net), Ok(prefix)) => in_network(ip, net, prefix),
            _ => false,
        };
    }

    if let Ok(want) = term.parse::<IpAddr>() {
        return ip == want;
    }

    if term.ends_with('.') || term.ends_with(':') {
        return ip.to_string().starts_with(term);
    }

    false
}

/// in_network reports whether `ip` falls inside `network`/`prefix`.
fn in_network(ip: IpAddr, network: IpAddr, prefix: u8) -> bool {
    // Comparing the leading `prefix` bits of the two addresses as bytes
    // avoids any 32- or 128-bit shift special cases, including a /0 and a
    // full-length mask.
    let (a, b) = match (ip, network) {
        (IpAddr::V4(a), IpAddr::V4(b)) => (a.octets().to_vec(), b.octets().to_vec()),
        (IpAddr::V6(a), IpAddr::V6(b)) => (a.octets().to_vec(), b.octets().to_vec()),
        // A v4 term never matches a v6 address, or the other way round.
        _ => return false,
    };
    if prefix as usize > a.len() * 8 {
        return false;
    }
    let whole = prefix as usize / 8;
    if a[..whole] != b[..whole] {
        return false;
    }
    let remainder = prefix as usize % 8;
    if remainder == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - remainder);
    a[whole] & mask == b[whole] & mask
}

fn port_eq(port: Option<u16>, value: &str) -> bool {
    match (port, value.parse::<u16>()) {
        (Some(p), Ok(want)) => p == want,
        _ => false,
    }
}
