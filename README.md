# Hermes

Hermes is a DNS resolver written in Rust.

The name comes from Hermes, the messenger from Greek mythology. In this project,
that maps to the core job of carrying DNS messages between clients and name
servers while parsing and preserving the DNS wire format.

## Current State

Hermes is under active development. It currently behaves as a small UDP
forwarding resolver rather than a complete recursive resolver.

The binary listens on `127.0.0.1:8080`, accepts DNS packets over UDP, forwards
them to the upstream resolver at `8.8.8.8:53`, decodes the response into
internal DNS message structures, re-encodes it, and sends the response back to
the original client.

## What Works Today

- UDP listener for local DNS traffic
- Forwarding DNS queries to Google DNS
- DNS packet reader and writer helpers
- DNS header, flags, question, name, and record parsing
- DNS name encoding and decoding, including compressed names
- DNS message encoding and decoding across question, answer, authority, and
  additional sections
- Record data support for `A`, `AAAA`, `NS`, and unknown record data
- Unit tests for DNS round trips and core packet components

## Not Implemented Yet

- Recursive resolution from root and authoritative name servers
- DNS caching and TTL-based expiry
- Configurable listen address or upstream resolver
- Timeout and retry behavior
- TCP fallback for truncated responses
- Full EDNS-specific handling
- CLI or configuration file support
- Production-grade validation and error handling

## Development History

Hermes started as a crate named `dns-resolver` with a compact first
implementation. The repository history shows the project moving toward clearer
DNS wire-format boundaries over time:

- `PacketReader` and `PacketWriter` provide primitive byte-level IO.
- DNS concepts such as names, questions, headers, flags, and records were moved
  out of the generic reader into dedicated modules.
- `Decode` and `Encode` traits were introduced for DNS structures.
- Message support expanded from questions and answers to authority and
  additional sections.
- Recent changes renamed the crate to `hermes` and added tests that verify DNS
  messages preserve fields across decode/encode round trips.

## Running

Start the resolver with:

```sh
cargo run
```

Then point a DNS client at `127.0.0.1` on port `8080`.

For example:

```sh
dig @127.0.0.1 -p 8080 example.com
```

## Testing

Run the test suite with:

```sh
cargo test
```

At the time this README was written, the existing test suite passes, with
compiler warnings for unused or not-yet-wired code paths that are still part of
the in-progress resolver design.
