# Changelog

## 0.1.0 — first release

- Managed crypto core: X25519, XSalsa20-Poly1305 (NaCl `crypto_box`), byte-compatible with libsodium.
- UDP transport (dual stack), packet dispatcher, LAN discovery.
- DHT: k-buckets, iterative lookups, friend IP search, crypto request routing, NAT hole punching.
- Onion: relay, announce server, client (announce, friend search, data packets, DHT key exchange).
- net_crypto: cookies, handshake, lossless and lossy packets, retransmission, congestion control.
- Messenger: friend requests, messages, actions, read receipts, name, status message, user status,
  typing, custom packets, file transfers.
- Profiles: toxcore savedata format (unknown sections preserved) and encrypted `toxEsave` profiles;
  `ToxPassKey` to derive a passphrase key once and reuse it.
- Public API: `Tox`, `ToxOptions`, events, `ToxException`.
- Interop tests against c-toxcore v0.2.23.

Not implemented yet: TCP relays and proxies, ToxAV, conferences and group chats.
