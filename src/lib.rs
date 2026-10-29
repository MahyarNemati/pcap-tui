//! pcap-tui reads packet capture files and decodes them.
//!
//! The crate is split so that everything except the terminal front end is a
//! library: the readers, the decoders and the filter engine are plain
//! functions over bytes, which is what makes them testable without a network
//! interface, without root, and without libpcap.

pub mod app;
pub mod decode;
pub mod live;
pub mod pcap;
pub mod ui;
