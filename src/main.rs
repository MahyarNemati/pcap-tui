//! pcap-tui: a terminal packet analyser.

use pcap_tui::{app, live, pcap, ui};

use std::io;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use app::{App, Pane};

#[derive(Debug, Parser)]
#[command(
    name = "pcap-tui",
    version,
    about = "Read a pcap/pcapng file (or capture live) and browse the packets in a TUI",
    after_help = "EXAMPLES:\n  pcap-tui capture.pcap                 browse a file\n  \
                  pcap-tui capture.pcapng -f 'tcp: port:443'  open with a filter applied\n  \
                  pcap-tui summary capture.pcap         protocol and conversation totals\n  \
                  pcap-tui dump capture.pcap            one line per packet, for grep\n  \
                  sudo pcap-tui live en0                live capture (needs --features live)\n\n\
                  Live capture needs libpcap and root. Reading files needs neither, which is\n\
                  why it is the default and why the decoders are tested that way."
)]
struct Args {
    /// A capture file to browse.
    file: Option<PathBuf>,

    /// Apply a display filter at startup.
    #[arg(short, long)]
    filter: Option<String>,

    /// Stop after this many packets.
    #[arg(short = 'n', long)]
    limit: Option<usize>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print protocol and conversation totals, without the TUI.
    Summary {
        file: PathBuf,
        /// How many conversations to list.
        #[arg(long, default_value_t = 10)]
        top: usize,
    },
    /// Print one line per packet, for piping into grep or awk.
    Dump {
        file: PathBuf,
        #[arg(short, long)]
        filter: Option<String>,
        #[arg(short = 'n', long)]
        limit: Option<usize>,
    },
    /// List the interfaces available for live capture.
    Devices,
    /// Capture live traffic. Needs --features live and usually root.
    Live {
        /// Interface name, or "any".
        #[arg(default_value = "any")]
        device: String,
        /// A BPF capture filter, compiled by libpcap and run in the kernel.
        #[arg(short, long)]
        bpf: Option<String>,
        /// Bytes to capture per packet.
        #[arg(long, default_value_t = 262144)]
        snaplen: i32,
        /// Put the interface in promiscuous mode.
        #[arg(long)]
        promiscuous: bool,
    },
}

fn main() -> Result<()> {
    let args = Args::parse();

    match args.command {
        Some(Command::Summary { file, top }) => cmd_summary(&file, top),
        Some(Command::Dump {
            file,
            filter,
            limit,
        }) => cmd_dump(&file, filter.as_deref(), limit),
        Some(Command::Devices) => cmd_devices(),
        Some(Command::Live {
            device,
            bpf,
            snaplen,
            promiscuous,
        }) => cmd_live(&device, bpf.as_deref(), snaplen, promiscuous, args.filter),
        None => match args.file {
            Some(file) => cmd_browse(&file, args.filter, args.limit),
            None => {
                // No file and no subcommand: say what to do rather than
                // opening an empty viewer.
                bail!("give a capture file, or a subcommand. Try --help.")
            }
        },
    }
}

/// load reads a whole capture into an App.
fn load(file: &Path, limit: Option<usize>) -> Result<App> {
    let mut reader = pcap::Reader::open(file)?;
    let format = format!(
        "{}{}, {}",
        reader.format_name(),
        if reader.big_endian() {
            ", big-endian"
        } else {
            ""
        },
        reader.link_type().name()
    );
    let mut app = App::new(file.display().to_string(), format);

    let mut n = 0usize;
    while let Some(packet) = reader.next_packet()? {
        app.push(packet);
        n += 1;
        if let Some(max) = limit {
            if n >= max {
                break;
            }
        }
    }
    // Start at the top of a file: following the end is for live capture.
    app.follow = false;
    app.first();
    Ok(app)
}

fn cmd_browse(file: &Path, filter: Option<String>, limit: Option<usize>) -> Result<()> {
    let mut app = load(file, limit)?;
    if let Some(f) = filter {
        app.set_filter(f);
    }
    if app.is_empty() {
        println!("{} contains no packets", file.display());
        return Ok(());
    }
    run_tui(app, None)
}

fn cmd_summary(file: &Path, top: usize) -> Result<()> {
    let app = load(file, None)?;
    let (bytes, span) = app.summary();

    println!("{}", app.source);
    println!("format:   {}", app.format);
    println!("packets:  {}", app.len());
    println!("bytes:    {} ({})", bytes, human_bytes(bytes));

    if let Some((first, last)) = span {
        let dur = last.duration_since(first).unwrap_or_default();
        println!(
            "span:     {} → {} ({:.3}s)",
            ui::format_time_full(first),
            ui::format_time(last),
            dur.as_secs_f64()
        );
        if dur.as_secs_f64() > 0.0 {
            println!(
                "rate:     {:.0} packets/s, {}/s",
                app.len() as f64 / dur.as_secs_f64(),
                human_bytes((bytes as f64 / dur.as_secs_f64()) as u64)
            );
        }
    }

    println!("\nprotocols");
    let stats = app.protocol_stats();
    let total = app.len().max(1);
    for (proto, count, bytes) in &stats {
        println!(
            "  {:<14} {:>8} packets  {:>5.1}%  {:>10}",
            proto,
            count,
            100.0 * *count as f64 / total as f64,
            human_bytes(*bytes)
        );
    }

    println!("\ntop {top} conversations");
    for (flow, count, bytes) in app.top_flows(top) {
        println!(
            "  {:<52} {:>7} packets  {:>10}",
            flow,
            count,
            human_bytes(bytes)
        );
    }
    Ok(())
}

fn cmd_dump(file: &Path, filter: Option<&str>, limit: Option<usize>) -> Result<()> {
    // A plain-text mode exists because the most useful thing about a packet
    // list is often grep, and a TUI cannot be piped.
    let mut app = load(file, limit)?;
    if let Some(f) = filter {
        if let Some(err) = app::validate_filter(f) {
            bail!("{err}");
        }
        app.set_filter(f.to_string());
    }

    for (_, row) in app.visible_rows() {
        println!(
            "{:>7}  {}  {:<46} {:<10} {:>6}  {}",
            row.packet.number,
            ui::format_time(row.packet.timestamp),
            row.decoded.flow(),
            row.decoded.top_protocol,
            row.packet.original_len,
            row.decoded.info
        );
    }
    Ok(())
}

fn cmd_devices() -> Result<()> {
    if !live::available() {
        println!("This build has no live capture support.");
        println!("Rebuild with:  cargo build --features live");
        println!("It needs libpcap installed, and capturing needs root or CAP_NET_RAW.");
        return Ok(());
    }
    let devices = live::list_devices()?;
    if devices.is_empty() {
        println!("No capture devices found (do you have permission?)");
        return Ok(());
    }
    for (name, desc) in devices {
        match desc {
            Some(d) => println!("{name:<16} {d}"),
            None => println!("{name}"),
        }
    }
    Ok(())
}

fn cmd_live(
    device: &str,
    bpf: Option<&str>,
    snaplen: i32,
    promiscuous: bool,
    display_filter: Option<String>,
) -> Result<()> {
    if !live::available() {
        bail!(
            "live capture is not compiled in.\n\
             Rebuild with:  cargo build --features live\n\
             It needs libpcap, and capturing needs root or CAP_NET_RAW.\n\n\
             To try the viewer without capturing, open a capture file:\n  \
             pcap-tui capture.pcap"
        );
    }

    let (tx, rx) = mpsc::channel();
    let dev = device.to_string();
    let filter = bpf.map(|s| s.to_string());
    std::thread::spawn(move || {
        if let Err(e) = live::capture(&dev, filter.as_deref(), snaplen, promiscuous, tx) {
            eprintln!("capture stopped: {e:#}");
        }
    });

    let mut app = App::new(
        format!(
            "live:{device}{}",
            bpf.map(|b| format!(" [{b}]")).unwrap_or_default()
        ),
        "live".into(),
    );
    if let Some(f) = display_filter {
        app.set_filter(f);
    }
    run_tui(app, Some(rx))
}

/// run_tui owns the terminal and the event loop.
fn run_tui(mut app: App, live_rx: Option<mpsc::Receiver<pcap::Packet>>) -> Result<()> {
    enable_raw_mode().context("enable raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).context("enter alternate screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("create terminal")?;

    let result = event_loop(&mut terminal, &mut app, live_rx);

    // Restore the terminal even on error. Leaving a terminal in raw mode with
    // the alternate screen active is the worst possible way for a TUI to
    // fail: the user's shell is unusable afterwards.
    disable_raw_mode().ok();
    execute!(terminal.backend_mut(), LeaveAlternateScreen).ok();
    terminal.show_cursor().ok();

    result
}

fn event_loop<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
    live_rx: Option<mpsc::Receiver<pcap::Packet>>,
) -> Result<()> {
    let tick = Duration::from_millis(100);
    let mut last_draw = Instant::now() - tick;

    loop {
        // Drain live packets before drawing, so a burst becomes one redraw
        // rather than one per packet.
        if let Some(rx) = &live_rx {
            while let Ok(packet) = rx.try_recv() {
                // The capture thread sends a zero packet as a keepalive on a
                // quiet link; it is not a real packet.
                if packet.number != 0 {
                    app.push(packet);
                }
            }
        }

        if last_draw.elapsed() >= tick {
            terminal
                .draw(|f| ui::draw(f, app))
                // The backend error type is generic and not necessarily
                // 'static, so it cannot go through anyhow's context().
                .map_err(|e| anyhow::anyhow!("draw: {e}"))?;
            last_draw = Instant::now();
        }

        if !event::poll(tick).context("poll input")? {
            continue;
        }
        let Event::Key(key) = event::read().context("read input")? else {
            continue;
        };
        // Only act on presses: a key repeat or release would double every
        // action on terminals that report them.
        if key.kind != KeyEventKind::Press {
            continue;
        }

        if app.editing_filter {
            handle_filter_key(app, key);
            // Force a redraw so typing feels immediate.
            last_draw = Instant::now() - tick;
            continue;
        }

        if handle_key(app, key, terminal.size().map(|s| s.height).unwrap_or(24)) {
            return Ok(());
        }
        last_draw = Instant::now() - tick;
    }
}

/// handle_filter_key edits the filter. Returns nothing: filter mode cannot
/// quit the application, which is deliberate -- 'q' must be typeable.
fn handle_filter_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.editing_filter = false;
        }
        KeyCode::Enter => {
            app.editing_filter = false;
        }
        KeyCode::Backspace => app.pop_filter_char(),
        KeyCode::Char(c) => app.push_filter_char(c),
        _ => {}
    }
}

/// handle_key processes a key press. Returns true to quit.
fn handle_key(app: &mut App, key: KeyEvent, height: u16) -> bool {
    let page = (height.saturating_sub(6) as usize).max(1);
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);

    match key.code {
        KeyCode::Char('q') | KeyCode::Esc if !app.show_help => return true,
        KeyCode::Char('c') if ctrl => return true,
        KeyCode::Char('?') => app.show_help = !app.show_help,
        KeyCode::Esc if app.show_help => app.show_help = false,

        KeyCode::Char('/') => {
            app.editing_filter = true;
        }
        KeyCode::Char('c') => app.clear_filter(),

        KeyCode::Tab => {
            app.pane = match app.pane {
                Pane::List => Pane::Detail,
                Pane::Detail => Pane::List,
            }
        }

        KeyCode::Char('j') | KeyCode::Down => match app.pane {
            Pane::List => app.next(),
            Pane::Detail => app.detail_scroll = app.detail_scroll.saturating_add(1),
        },
        KeyCode::Char('k') | KeyCode::Up => match app.pane {
            Pane::List => app.previous(),
            Pane::Detail => app.detail_scroll = app.detail_scroll.saturating_sub(1),
        },
        // Capital J/K scroll the detail pane regardless of focus, because
        // reaching for Tab to read a hex dump gets old quickly.
        KeyCode::Char('J') => app.detail_scroll = app.detail_scroll.saturating_add(1),
        KeyCode::Char('K') => app.detail_scroll = app.detail_scroll.saturating_sub(1),

        KeyCode::Char('d') if ctrl => app.page_down(page),
        KeyCode::Char('u') if ctrl => app.page_up(page),
        KeyCode::PageDown => app.page_down(page),
        KeyCode::PageUp => app.page_up(page),
        KeyCode::Char('g') | KeyCode::Home => app.first(),
        KeyCode::Char('G') | KeyCode::End => app.last(),
        _ => {}
    }
    false
}

fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}
