# A container is an awkward home for a packet analyser -- live capture needs
# the host's network namespace and NET_RAW -- but it is the easiest way to
# read a capture file on a machine with no Rust toolchain:
#
#   docker build -t pcap-tui .
#   docker run --rm -v "$PWD:/captures" pcap-tui summary capture.pcap
#
# The TUI needs a terminal, so pass -it for that:
#
#   docker run --rm -it -v "$PWD:/captures" pcap-tui capture.pcap

FROM rust:1.99-slim-trixie AS build
WORKDIR /src

COPY Cargo.toml Cargo.lock rustfmt.toml ./
COPY src ./src
COPY examples ./examples
# --locked: the image is built from the committed lockfile, not from whatever
# resolves today.
RUN cargo build --release --locked

FROM debian:trixie-slim
# Nothing here talks to the network, so there are no certificates to install
# and no packages to add: the image is the binary.
COPY --from=build /src/target/release/pcap-tui /usr/local/bin/pcap-tui

# Reading a capture file needs no privileges, so do not run as root.
RUN useradd --create-home --uid 10001 analyst
USER analyst
WORKDIR /captures

ENTRYPOINT ["pcap-tui"]
CMD ["--help"]
