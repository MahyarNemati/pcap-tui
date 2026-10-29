//! Live capture, behind the `live` feature.
//!
//! Separated and optional for a reason worth stating: live capture needs
//! libpcap installed *and* elevated privileges, and most of the time neither
//! is available -- not in CI, not in a container, not on a locked-down
//! workstation. Making it optional means the decoders and the TUI build, test
//! and run everywhere against capture files, which is how they were actually
//! developed.

#[cfg(feature = "live")]
mod imp {
    use anyhow::{Context, Result};
    use std::sync::mpsc::Sender;
    use std::time::{Duration, UNIX_EPOCH};

    use crate::pcap::{LinkType, Packet};

    /// Lists the interfaces that can be captured on.
    pub fn list_devices() -> Result<Vec<(String, Option<String>)>> {
        let devices = pcap::Device::list().context("list capture devices")?;
        Ok(devices.into_iter().map(|d| (d.name, d.desc)).collect())
    }

    /// Captures until the channel is dropped, sending each packet.
    ///
    /// `snaplen` bounds how much of each packet is captured. The default of
    /// 262144 captures everything; a smaller value reduces I/O at the cost of
    /// truncating payloads, which the viewer then flags.
    pub fn capture(
        device: &str,
        filter: Option<&str>,
        snaplen: i32,
        promiscuous: bool,
        tx: Sender<Packet>,
    ) -> Result<()> {
        let device = if device == "any" || device.is_empty() {
            pcap::Device::lookup()
                .context("find a default capture device")?
                .context("no capture device available")?
        } else {
            pcap::Device::from(device)
        };

        let mut cap = pcap::Capture::from_device(device)
            .context("open capture device")?
            .promisc(promiscuous)
            .snaplen(snaplen)
            // A timeout lets the loop notice a dropped channel rather than
            // blocking forever on a quiet network.
            .timeout(250)
            // Immediate mode: without it libpcap buffers packets and the TUI
            // appears frozen on low-traffic links.
            .immediate_mode(true)
            .open()
            .context("start capture (this usually needs root or CAP_NET_RAW)")?;

        if let Some(expr) = filter {
            // A BPF filter is compiled by libpcap and runs in the kernel,
            // which is why it is far cheaper than filtering in the viewer --
            // and why it is offered separately from the display filter.
            cap.filter(expr, true)
                .with_context(|| format!("compile BPF filter {expr:?}"))?;
        }

        let link_type = LinkType::from_u32(cap.get_datalink().0 as u32);
        let mut number = 0u64;

        loop {
            match cap.next_packet() {
                Ok(p) => {
                    number += 1;
                    let ts = UNIX_EPOCH
                        + Duration::new(
                            p.header.ts.tv_sec as u64,
                            (p.header.ts.tv_usec as u32).saturating_mul(1000),
                        );
                    let packet = Packet {
                        number,
                        timestamp: ts,
                        original_len: p.header.len,
                        data: p.data.to_vec(),
                        link_type,
                    };
                    // A closed channel means the UI has exited.
                    if tx.send(packet).is_err() {
                        return Ok(());
                    }
                }
                Err(pcap::Error::TimeoutExpired) => {
                    // Normal on a quiet link. Probe the channel so the thread
                    // exits promptly once the UI is gone.
                    if tx
                        .send(Packet {
                            number: 0,
                            timestamp: UNIX_EPOCH,
                            original_len: 0,
                            data: Vec::new(),
                            link_type,
                        })
                        .is_err()
                    {
                        return Ok(());
                    }
                }
                Err(pcap::Error::NoMorePackets) => return Ok(()),
                Err(e) => return Err(e).context("read packet"),
            }
        }
    }
}

#[cfg(not(feature = "live"))]
mod imp {
    use anyhow::{bail, Result};
    use std::sync::mpsc::Sender;

    use crate::pcap::Packet;

    const MESSAGE: &str = "live capture is not compiled in; rebuild with --features live \
(it needs libpcap and usually root)";

    pub fn list_devices() -> Result<Vec<(String, Option<String>)>> {
        bail!(MESSAGE)
    }

    pub fn capture(
        _device: &str,
        _filter: Option<&str>,
        _snaplen: i32,
        _promiscuous: bool,
        _tx: Sender<Packet>,
    ) -> Result<()> {
        bail!(MESSAGE)
    }
}

pub use imp::{capture, list_devices};

/// Reports whether this build can capture live traffic.
pub const fn available() -> bool {
    cfg!(feature = "live")
}
