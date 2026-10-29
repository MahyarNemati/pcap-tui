# pcap-tui

A terminal packet analyser. It reads `.pcap` and `.pcapng` files, decodes the
protocols you actually run into, and shows them in a two-pane TUI with a
display filter. It can also capture live, but that is the optional part.

```text
 pcap-tui  sample.pcap [pcap, Ethernet] 9 packets   ? for help
┌ packets (focused) ───────────────────────────────────────────────────────────────────────────┐
│#       time            source → destination           proto      len     info                │
│2       22:13:20.012400 10.0.0.53:53 → 10.0.0.1:54120  DNS        106     response www.example│
│3       22:13:20.013300 10.0.0.1:49812 → 93.184.216.34 TCP        54      [S] seq=1 win=64240 │
│4       22:13:20.031600 93.184.216.34:443 → 10.0.0.1:4 TCP        54      [S.] seq=9001 win=64│
│5       22:13:20.031750 10.0.0.1:49812 → 93.184.216.34 TCP        54      [.] seq=2 win=64240 │
│6       22:13:20.032150 10.0.0.1:49812 → 93.184.216.34 TLS        130     ClientHello www.exam│
└──────────────────────────────────────────────────────────────────────────────────────────────┘
┌ detail ──────────────────────────────────────────────────────────────────────────────────────┐
│     frame  #4  2023-11-14 22:13:20.031600  54 bytes on the wire, 54 captured                 │
│  ethernet  02:00:00:00:00:fe → 02:00:00:00:00:01  ethertype 0x0800                           │
│        ip  93.184.216.34 → 10.0.0.1  ttl/hop-limit 64                                        │
│ transport  TCP  443 → 49812  flags [S.]  seq 9001  ack 2  win 64240                          │
│       tcp  [S.] seq=9001 win=64240 len=0  (0 payload bytes)                                  │
│                                                                                              │
│54 captured bytes, no payload                                                                 │
│00000000  02 00 00 00 00 01 02 00  00 00 00 fe 08 00 45 00  |..............E.|                │
│00000010  00 28 04 d2 00 00 40 06  36 23 5d b8 d8 22 0a 00  |.(....@.6#].."..|                │
│00000020  00 01 01 bb c2 94 00 00  23 29 00 00 00 02 50 12  |........#)....P.|                │
│00000030  fa f0 00 00 00 00                                 |......|                          │
│                                                                                              │
└──────────────────────────────────────────────────────────────────────────────────────────────┘
 packet 4 of 9   j/k move  Tab pane  / filter  q quit
```

## Why this exists

Reading a capture usually means `tcpdump -r`, which is dense and
unscrollable, or Wireshark, which is a GUI you cannot run over SSH. This sits
between them: it scrolls, it filters, it shows a hex dump, and it runs in a
terminal on a server.

The design decision worth pointing at is that **everything except live
capture works on a file**, with no libpcap, no root, and no network
interface. The file readers are written from the pcap and pcapng
specifications rather than wrapping libpcap, so the decoders could be
developed and tested the same way they run in CI: against bytes.

## Install and run

Needs a Rust toolchain (1.89 or newer). Nothing else.

```bash
cargo build --release
```

There is no capture file to hand on a fresh checkout, so one is generated:

```bash
make sample              # writes sample.pcap
cargo run -- sample.pcap # open it
```

Or in one step:

```bash
make demo
```

### Reading a file

```bash
pcap-tui capture.pcap                        # browse it
pcap-tui capture.pcapng -f 'tcp:1 port:443'  # open with a filter applied
pcap-tui capture.pcap -n 10000               # stop after 10000 packets
```

### Without the TUI

A TUI cannot be piped, so the two things you most often want from a capture
are also plain commands:

```bash
pcap-tui summary capture.pcap           # protocol and conversation totals
pcap-tui dump capture.pcap              # one line per packet
pcap-tui dump capture.pcap -f proto:dns | awk '{print $4}' | sort | uniq -c
```

`summary` prints what a capture *is* before you start reading it:

```
capture.pcap
format:   pcap, Ethernet
packets:  9
bytes:    716 (716 B)
span:     2023-11-14 22:13:20.000000 → 22:13:20.587150 (0.587s)
rate:     15 packets/s, 1.2 KiB/s

protocols
  TCP                   3 packets   33.3%       162 B
  DNS                   2 packets   22.2%       181 B
  ARP                   1 packets   11.1%        42 B
  HTTP                  1 packets   11.1%       127 B
  ICMP                  1 packets   11.1%        74 B
  TLS                   1 packets   11.1%       130 B

top 10 conversations
  10.0.0.1:49812 ⇄ 93.184.216.34:443      4 packets       292 B
  10.0.0.1:54120 ⇄ 10.0.0.53:53           2 packets       181 B
```

Conversations are counted in both directions as one row, which is the only
way the list answers "who is doing all the talking".

### Capturing live

Live capture needs libpcap and root, so it is behind a feature flag and off
by default:

```bash
cargo build --release --features live
pcap-tui devices              # what can be captured on
sudo pcap-tui live en0
sudo pcap-tui live en0 --bpf 'tcp port 443'
```

`--bpf` is compiled by libpcap and runs in the kernel, so it is much cheaper
than the display filter and it is the right place to cut down a busy link.
The display filter then narrows what is already captured, without discarding
it.

Without the feature, `pcap-tui live` says so and tells you how to rebuild,
rather than failing with a linker error.

### In Docker

```bash
docker build -t pcap-tui .
docker run --rm -v "$PWD:/captures:ro" pcap-tui summary capture.pcap
docker run --rm -it -v "$PWD:/captures:ro" pcap-tui capture.pcap
```

The image carries the binary and nothing else, and runs as a non-root user —
reading a capture file needs no privileges.

## Keys

| key | does |
| --- | --- |
| `j` / `k`, `↓` / `↑` | move in the focused pane |
| `J` / `K` | scroll the detail pane whatever is focused |
| `ctrl-d` / `ctrl-u`, `PgDn` / `PgUp` | page |
| `g` / `G`, `Home` / `End` | first / last packet |
| `Tab` | switch pane |
| `/` | edit the filter (`Enter` to apply, `Esc` to cancel) |
| `c` | clear the filter |
| `?` | help |
| `q`, `Esc`, `ctrl-c` | quit |

## The display filter

Space-separated terms, all of which must match. A `!` prefix negates a term.

```
proto:dns                     DNS packets
port:443 flag:syn             connections opening to 443
ip:10.0.0.5 !proto:arp        one host, without the ARP noise
src:10.0.0.0/8 !dst:10.0.0.0/8   traffic leaving the private range
minlen:1400                   large packets, so near-MTU traffic
example.com                   a bare term is a substring search
```

| key | matches |
| --- | --- |
| `ip:` `src:` `dst:` | an address, a CIDR network, or a textual prefix |
| `port:` `sport:` `dport:` | an exact port |
| `proto:` | the protocol label, as a substring |
| `tcp:` `udp:` | the transport protocol (the value is ignored) |
| `len:` `minlen:` `maxlen:` | the original packet length |
| `flag:` | a TCP flag by name (`syn`, `ack`, `fin`, `rst`, `psh`) or letter |

Address terms take three forms: an exact address (`10.0.0.5`,
`2001:db8::1`), a network (`10.0.0.0/24`), or a textual prefix with the
separator left on (`10.0.`, `2001:db8:`). The trailing separator is required
for the prefix form, because otherwise `ip:10.0.0.2` would also match
`10.0.0.254` -- a filter that quietly matches more than it was asked to is
worse than one that matches nothing.

A term with an unrecognised key is reported on screen. That matters more than
it sounds: without it, `prot:tcp` shows an empty list, which looks exactly
like a capture with nothing to show.

This is deliberately not a Wireshark display-filter or BPF parser. Either one
is a larger project than the whole of this one, and this covers what a person
types while reading a capture.

## What it decodes

Link: Ethernet II, 802.1Q and stacked (QinQ) VLAN tags, raw IP,
DLT_NULL/loopback, Linux cooked capture (`any`).

Network: IPv4 including options and fragmentation, IPv6 including the
extension-header chain, ARP, ICMP, ICMPv6.

Transport and above: TCP (with tcpdump-style flags), UDP, DNS and mDNS, TLS
(identified by its record header, with the SNI host pulled out of a
ClientHello), HTTP request and status lines, and a well-known-port table as
the last resort — labelled `(by port)`, so the guess is visible as a guess.

## How it is put together

```
src/pcap.rs    pcap and pcapng readers, written from the file formats
src/decode.rs  protocol decoders: bytes in, a Decoded struct out
src/app.rs     packet list, filter engine, statistics -- no rendering
src/ui.rs      rendering only -- no state
src/live.rs    libpcap capture, behind the `live` feature
src/main.rs    CLI, terminal setup, event loop
```

`app.rs` holds the state and `ui.rs` draws it, with nothing passing the other
way. That split is what lets the rendering be tested: a test renders into an
in-memory buffer and asserts on the text, so "the detail pane disappears on a
short terminal" is a test failure rather than something you find in use.

### Decoding bytes from the network

Every length in a packet header is attacker-controlled. The rule throughout
`decode.rs` is to never index without checking the length first, and the
tests are written to the same brief:

- **No length is trusted.** A record claiming 4 GiB is rejected rather than
  allocated; a TCP data offset, IPv4 IHL, UDP length and TLS extension length
  are each bounded by what is actually present.
- **DNS compression pointers are not followed at all.** A pointer to itself
  is a decompression loop, and nothing in a summary line needs the
  compressed form resolved.
- **The IPv6 extension-header chain is bounded.** A chain of zero-length
  headers pointing onwards would otherwise loop forever.
- **A hostname from a ClientHello is checked before it is printed.** It is
  attacker-controlled text heading for a terminal, where an escape sequence
  can move the cursor or rewrite the title.
- **Every prefix of a real packet is decoded in a test.** Truncation happens
  for mundane reasons — a short snaplen, a cut-off file — and a decoder that
  panics on one is useless on real captures.

### Known limitations

Stated rather than hidden:

- pcapng `if_tsresol` is not parsed, so timestamps assume the default
  microsecond resolution. A capture written with a different resolution will
  have wrongly scaled timestamps.
- TCP streams are not reassembled, so a request split across segments is only
  identified from the segment that carries its first bytes.
- IP fragments are not reassembled; a non-first fragment is labelled as a
  fragment rather than decoded.
- The display filter has no `or` and no parentheses.

## Tests

```bash
make test        # 96 tests
make lint        # fmt, clippy with warnings denied, both feature sets
make ci          # both
```

Every fixture is built byte by byte from the specification in
`tests/support/mod.rs`, including the malformed ones. That is on purpose: if
the tests produced fixtures with libpcap and read them back with this reader,
a shared misunderstanding of the format would cancel out and the tests would
pass against a wrong reader.

The suite covers both byte orders and both timestamp resolutions of classic
pcap; pcapng section, interface, enhanced-packet, simple-packet and unknown
blocks; corrupt and truncated files; each protocol above; every truncation
point of a real packet; a pseudo-random byte sweep under every link type; the
filter language and its error reporting; rendering at terminal sizes down to
1×1; and the `summary` and `dump` commands run as the real binary.

CI additionally builds the `live` feature against libpcap on Linux, checks the
crate against its stated minimum Rust version, builds the image and reads a
capture through it, and audits dependencies with `cargo audit`.

## Licence

MIT. See [LICENSE](LICENSE).
