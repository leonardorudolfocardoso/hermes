# Hermes

Hermes is a DNS resolver written in Rust.

The name comes from Hermes, the messenger from Greek mythology. In this project,
that maps to the core job of carrying DNS messages between clients and name
servers while parsing and preserving the DNS wire format.

## Current State

Hermes is under active development. It currently behaves as a small UDP
iterative resolver and is intended as a DNS learning project rather than a
production DNS server.

The binary listens on a user-provided address, accepts DNS queries over UDP,
and resolves them by querying root and authoritative name servers. It follows
referrals, uses glue records when available, and resolves name server addresses
when referrals do not include glue.

## What Works Today

- UDP listener for local DNS traffic
- Iterative resolution starting from the DNS root servers
- Referral following with IPv4 and IPv6 glue addresses
- Nested `A` and `AAAA` lookups for name servers without glue
- Failover across candidate name servers
- Query timeouts and limits for referral hops and nested lookups
- DNS response codes for malformed queries and resolution failures
- DNS packet reader and writer helpers
- DNS header, flags, question, name, and record parsing
- DNS name encoding and decoding, including compressed names
- DNS message encoding and decoding across question, answer, authority, and
  additional sections
- Record data support for `A`, `AAAA`, `NS`, and unknown record data
- Unit tests for DNS round trips, referral handling, resolution limits, and
  name server failover

## Not Implemented Yet

- DNS caching and TTL-based expiry
- CNAME-chain resolution
- TCP fallback for truncated responses
- Full EDNS-specific handling
- Configuration beyond the positional listen-address argument
- Validation of upstream transaction IDs, questions, and response flags
- Bailiwick validation for glue records
- Concurrent request handling and production-grade observability

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
- The resolver now performs iterative resolution from root servers through
  authoritative referrals instead of forwarding queries to a public resolver.

## Running

Start the resolver with:

```sh
cargo run -- 127.0.0.1:8080
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

The test suite currently passes. The compiler still reports warnings for a few
unused DNS accessors and flag helpers that are not yet wired into response
validation.
