//! Readers for the pcap and pcapng capture file formats.
//!
//! Written from the specifications rather than bound to libpcap, for a
//! specific reason: it means the decoders can be developed, tested and run
//! with no system library and no privileges. Live capture is an optional
//! feature; reading files is the default, and it is what makes the whole
//! project testable.
//!
//! The two formats are quite different:
//!
//! * **pcap** (classic) is a 24-byte file header followed by per-packet
//!   records. Simple, and still what most tools emit by default.
//! * **pcapng** is a block-structured format: a Section Header Block declares
//!   endianness, Interface Description Blocks declare link types and timestamp
//!   resolution, and Enhanced Packet Blocks carry the packets. More complex,
//!   but it is what `tcpdump` on a modern system and Wireshark produce.
//!
//! Both are byte-order sensitive, and getting that wrong is the classic bug:
//! a pcap file written on a different-endian machine has a byte-swapped magic
//! number, and a reader that ignores it reports absurd packet lengths.

use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};

/// Classic pcap magic, microsecond timestamps.
const MAGIC_USEC: u32 = 0xa1b2_c3d4;
/// Same, byte-swapped: the file came from a machine of the other endianness.
const MAGIC_USEC_SWAPPED: u32 = 0xd4c3_b2a1;
/// Nanosecond-timestamp variant, introduced by libpcap 1.5.
const MAGIC_NSEC: u32 = 0xa1b2_3c4d;
const MAGIC_NSEC_SWAPPED: u32 = 0x4d3c_b2a1;

/// pcapng Section Header Block type.
const PCAPNG_SHB: u32 = 0x0a0d_0d0a;
/// The byte-order magic inside an SHB.
const PCAPNG_BYTE_ORDER: u32 = 0x1a2b_3c4d;

/// Block types we care about.
const BLOCK_IDB: u32 = 0x0000_0001;
const BLOCK_EPB: u32 = 0x0000_0006;
const BLOCK_SPB: u32 = 0x0000_0003;

/// A refusal threshold for a declared packet length.
///
/// A corrupt or hostile file can claim a 4 GiB packet, and a reader that
/// trusts it allocates 4 GiB. 262144 is libpcap's own MAXIMUM_SNAPLEN.
const MAX_PACKET_LEN: u32 = 262_144;

/// Link-layer type, as recorded in the capture file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    /// DLT_EN10MB: an Ethernet header.
    Ethernet,
    /// DLT_RAW: the IP header starts immediately.
    Raw,
    /// DLT_NULL / DLT_LOOP: a 4-byte address-family header, as used on
    /// loopback interfaces.
    Null,
    /// DLT_LINUX_SLL: Linux "cooked" capture, used when capturing on `any`.
    LinuxSll,
    Other(u32),
}

impl LinkType {
    /// from_u32 maps a DLT value.
    pub fn from_u32(v: u32) -> Self {
        match v {
            0 => LinkType::Null,
            1 => LinkType::Ethernet,
            12 | 14 => LinkType::Raw,
            101 => LinkType::Raw,
            113 => LinkType::LinuxSll,
            108 => LinkType::Null, // DLT_LOOP, same shape as DLT_NULL
            other => LinkType::Other(other),
        }
    }

    /// Bytes to skip before the network-layer header.
    pub fn header_len(self) -> usize {
        match self {
            LinkType::Ethernet => 14,
            LinkType::Raw => 0,
            LinkType::Null => 4,
            LinkType::LinuxSll => 16,
            LinkType::Other(_) => 0,
        }
    }

    pub fn name(self) -> String {
        match self {
            LinkType::Ethernet => "Ethernet".into(),
            LinkType::Raw => "Raw IP".into(),
            LinkType::Null => "Null/Loopback".into(),
            LinkType::LinuxSll => "Linux cooked".into(),
            LinkType::Other(v) => format!("DLT {v}"),
        }
    }
}

/// One captured packet.
#[derive(Debug, Clone)]
pub struct Packet {
    /// Index in the capture, 1-based, as Wireshark numbers them.
    pub number: u64,
    pub timestamp: SystemTime,
    /// Length on the wire, which may exceed the captured bytes.
    pub original_len: u32,
    pub data: Vec<u8>,
    pub link_type: LinkType,
}

impl Packet {
    /// Reports whether the packet was truncated by the capture snaplen.
    ///
    /// Worth surfacing: a truncated packet means the decoder is working with
    /// an incomplete header, and "why does Wireshark show this differently"
    /// is usually this.
    pub fn truncated(&self) -> bool {
        self.original_len as usize > self.data.len()
    }

    /// Payload after the link-layer header.
    pub fn network_bytes(&self) -> &[u8] {
        let skip = self.link_type.header_len();
        if self.data.len() <= skip {
            &[]
        } else {
            &self.data[skip..]
        }
    }
}

/// A capture file reader.
pub struct Reader {
    inner: Box<dyn Read>,
    format: Format,
    /// Classic pcap has one link type for the whole file; pcapng has one per
    /// interface.
    link_types: Vec<LinkType>,
    big_endian: bool,
    nanos: bool,
    count: u64,
}

// A hand-written Debug: the reader owns a `dyn Read`, which cannot derive
// one, and the useful thing to print is the format and position anyway.
impl std::fmt::Debug for Reader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reader")
            .field("format", &self.format)
            .field("big_endian", &self.big_endian)
            .field("nanos", &self.nanos)
            .field("link_types", &self.link_types)
            .field("packets_read", &self.count)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Pcap,
    PcapNg,
}

impl Reader {
    /// Opens a capture file, detecting the format from its first four bytes.
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
        Self::from_reader(Box::new(BufReader::with_capacity(1 << 16, file)))
    }

    /// Builds a reader over any source.
    pub fn from_reader(mut inner: Box<dyn Read>) -> Result<Self> {
        let mut magic = [0u8; 4];
        inner
            .read_exact(&mut magic)
            .context("read file magic (is the file empty?)")?;
        let native = u32::from_le_bytes(magic);

        match native {
            MAGIC_USEC | MAGIC_NSEC => Ok(Reader {
                inner,
                format: Format::Pcap,
                link_types: Vec::new(),
                big_endian: false,
                nanos: native == MAGIC_NSEC,
                count: 0,
            })
            .and_then(|r| r.finish_pcap_header()),
            MAGIC_USEC_SWAPPED | MAGIC_NSEC_SWAPPED => Ok(Reader {
                inner,
                format: Format::Pcap,
                link_types: Vec::new(),
                big_endian: true,
                nanos: native == MAGIC_NSEC_SWAPPED,
                count: 0,
            })
            .and_then(|r| r.finish_pcap_header()),
            _ if u32::from_be_bytes(magic) == PCAPNG_SHB
                || u32::from_le_bytes(magic) == PCAPNG_SHB =>
            {
                let mut r = Reader {
                    inner,
                    format: Format::PcapNg,
                    link_types: Vec::new(),
                    big_endian: false,
                    nanos: false,
                    count: 0,
                };
                r.read_section_header()?;
                Ok(r)
            }
            other => {
                bail!("unrecognised capture format (magic {other:#010x}); expected pcap or pcapng")
            }
        }
    }

    /// Reads the remaining 20 bytes of a classic pcap header.
    fn finish_pcap_header(mut self) -> Result<Self> {
        let mut rest = [0u8; 20];
        self.inner
            .read_exact(&mut rest)
            .context("read pcap file header")?;
        // version major/minor, thiszone, sigfigs, snaplen, network
        let network = self.u32_at(&rest, 16);
        self.link_types.push(LinkType::from_u32(network));
        Ok(self)
    }

    /// Reads a pcapng Section Header Block, which declares the byte order for
    /// everything that follows.
    fn read_section_header(&mut self) -> Result<()> {
        // The block type has been consumed; read total length and byte-order
        // magic. Length is in the file's endianness, which is not yet known,
        // so read the byte-order magic first by peeking past it.
        let mut buf = [0u8; 8];
        self.inner
            .read_exact(&mut buf)
            .context("read section header block")?;

        let bom_le = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        self.big_endian = bom_le != PCAPNG_BYTE_ORDER;

        let total_len = self.u32_at(&buf, 0);
        if !(28..=(1 << 24)).contains(&total_len) {
            bail!("implausible section header block length {total_len}");
        }
        // Skip the rest of the block: version, section length and options.
        // total_len covers type(4) + len(4) + body + trailing len(4); 12 of
        // those bytes are already read or accounted for.
        let remaining = total_len as usize - 12;
        self.skip(remaining)?;
        Ok(())
    }

    /// Returns the next packet, or None at end of file.
    pub fn next_packet(&mut self) -> Result<Option<Packet>> {
        match self.format {
            Format::Pcap => self.next_pcap(),
            Format::PcapNg => self.next_pcapng(),
        }
    }

    fn next_pcap(&mut self) -> Result<Option<Packet>> {
        let mut header = [0u8; 16];
        match self.inner.read_exact(&mut header) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e).context("read packet record header"),
        }

        let ts_sec = self.u32_at(&header, 0) as u64;
        let ts_frac = self.u32_at(&header, 4) as u64;
        let incl_len = self.u32_at(&header, 8);
        let orig_len = self.u32_at(&header, 12);

        // Trusting a declared length is how a reader is made to allocate
        // gigabytes from a corrupt file.
        if incl_len > MAX_PACKET_LEN {
            bail!("packet {} declares {incl_len} captured bytes, which exceeds the {MAX_PACKET_LEN}-byte limit", self.count + 1);
        }

        let mut data = vec![0u8; incl_len as usize];
        self.inner
            .read_exact(&mut data)
            .context("read packet data (file truncated?)")?;

        self.count += 1;
        Ok(Some(Packet {
            number: self.count,
            timestamp: self.timestamp(ts_sec, ts_frac),
            original_len: orig_len,
            data,
            link_type: self
                .link_types
                .first()
                .copied()
                .unwrap_or(LinkType::Ethernet),
        }))
    }

    fn next_pcapng(&mut self) -> Result<Option<Packet>> {
        loop {
            let mut head = [0u8; 8];
            match self.inner.read_exact(&mut head) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(e) => return Err(e).context("read block header"),
            }

            let block_type = self.u32_at(&head, 0);
            let total_len = self.u32_at(&head, 4);
            if total_len < 12 || total_len as u64 > (1 << 26) {
                bail!("implausible block length {total_len} for block type {block_type:#010x}");
            }
            // The body excludes the 8 bytes read and the trailing length.
            let body_len = total_len as usize - 12;

            match block_type {
                BLOCK_IDB => {
                    let body = self.read_exact_vec(body_len)?;
                    self.skip(4)?; // trailing total length
                    if body.len() >= 2 {
                        let linktype = u16::from_le_bytes([body[0], body[1]]);
                        let linktype = if self.big_endian {
                            u16::from_be_bytes([body[0], body[1]])
                        } else {
                            linktype
                        };
                        self.link_types.push(LinkType::from_u32(linktype as u32));
                    } else {
                        self.link_types.push(LinkType::Ethernet);
                    }
                }
                BLOCK_EPB => {
                    let body = self.read_exact_vec(body_len)?;
                    self.skip(4)?;
                    if body.len() < 20 {
                        bail!("enhanced packet block is too short ({} bytes)", body.len());
                    }
                    let iface = self.u32_at(&body, 0) as usize;
                    let ts_high = self.u32_at(&body, 4) as u64;
                    let ts_low = self.u32_at(&body, 8) as u64;
                    let captured = self.u32_at(&body, 12);
                    let original = self.u32_at(&body, 16);

                    if captured > MAX_PACKET_LEN {
                        bail!("packet declares {captured} captured bytes, above the {MAX_PACKET_LEN}-byte limit");
                    }
                    let end = 20 + captured as usize;
                    if end > body.len() {
                        bail!(
                            "enhanced packet block claims {captured} bytes but holds {}",
                            body.len() - 20
                        );
                    }

                    self.count += 1;
                    // pcapng timestamps are a 64-bit count of units given by
                    // the interface's if_tsresol option, which defaults to
                    // microseconds. Options are not parsed here, so the
                    // default is assumed -- documented as a limitation.
                    let micros = (ts_high << 32) | ts_low;
                    return Ok(Some(Packet {
                        number: self.count,
                        timestamp: UNIX_EPOCH + Duration::from_micros(micros),
                        original_len: original,
                        data: body[20..end].to_vec(),
                        link_type: self
                            .link_types
                            .get(iface)
                            .copied()
                            .unwrap_or(LinkType::Ethernet),
                    }));
                }
                BLOCK_SPB => {
                    // A simple packet block has no timestamp and no captured
                    // length: the whole body is the packet.
                    let body = self.read_exact_vec(body_len)?;
                    self.skip(4)?;
                    if body.len() < 4 {
                        continue;
                    }
                    let original = self.u32_at(&body, 0);
                    // The body is padded to a 4-byte boundary and a simple
                    // packet block carries no captured length, so the only
                    // way to tell packet bytes from padding is the original
                    // length -- capped by what is actually present, since a
                    // short snaplen leaves fewer bytes than that.
                    let end = (original as usize)
                        .min(body.len() - 4)
                        .min(MAX_PACKET_LEN as usize);
                    self.count += 1;
                    return Ok(Some(Packet {
                        number: self.count,
                        timestamp: UNIX_EPOCH,
                        original_len: original,
                        data: body[4..4 + end].to_vec(),
                        link_type: self
                            .link_types
                            .first()
                            .copied()
                            .unwrap_or(LinkType::Ethernet),
                    }));
                }
                PCAPNG_SHB => {
                    // A new section. Re-read its byte order rather than
                    // assuming it matches: a concatenated capture can change
                    // endianness partway through.
                    let body = self.read_exact_vec(body_len)?;
                    self.skip(4)?;
                    if body.len() >= 4 {
                        let bom = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
                        self.big_endian = bom != PCAPNG_BYTE_ORDER;
                    }
                    self.link_types.clear();
                }
                _ => {
                    // Unknown blocks are skipped, which is what the format is
                    // designed for: a reader must tolerate block types it
                    // does not know.
                    self.skip(body_len + 4)?;
                }
            }
        }
    }

    fn timestamp(&self, secs: u64, frac: u64) -> SystemTime {
        let dur = if self.nanos {
            Duration::new(secs, frac.min(999_999_999) as u32)
        } else {
            Duration::new(secs, (frac.min(999_999) * 1000) as u32)
        };
        UNIX_EPOCH + dur
    }

    fn u32_at(&self, buf: &[u8], offset: usize) -> u32 {
        let b = [
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ];
        if self.big_endian {
            u32::from_be_bytes(b)
        } else {
            u32::from_le_bytes(b)
        }
    }

    fn read_exact_vec(&mut self, n: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; n];
        self.inner.read_exact(&mut buf).context("read block body")?;
        Ok(buf)
    }

    fn skip(&mut self, n: usize) -> Result<()> {
        let mut remaining = n;
        let mut scratch = [0u8; 4096];
        while remaining > 0 {
            let want = remaining.min(scratch.len());
            self.inner
                .read_exact(&mut scratch[..want])
                .context("skip bytes")?;
            remaining -= want;
        }
        Ok(())
    }

    /// The link type of the first interface, for display.
    pub fn link_type(&self) -> LinkType {
        self.link_types
            .first()
            .copied()
            .unwrap_or(LinkType::Ethernet)
    }

    /// The format that was detected.
    pub fn format_name(&self) -> &'static str {
        match self.format {
            Format::Pcap => "pcap",
            Format::PcapNg => "pcapng",
        }
    }

    /// Whether the file is big-endian, which is worth showing: it is the
    /// detail that breaks naive readers.
    pub fn big_endian(&self) -> bool {
        self.big_endian
    }
}
