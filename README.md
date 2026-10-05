# Toxide

A fully managed .NET implementation of the [Tox](https://tox.chat) protocol, wire-compatible with
[c-toxcore](https://github.com/TokTok/c-toxcore) — the library behind qTox, uTox, Toxic and most other
Tox clients. No native libraries: Toxide is plain C# on top of .NET 8 and BouncyCastle.

```
dotnet add package Toxide
```

## Features

| Area | Status |
|---|---|
| Identity, Tox ID (nospam + checksum) | ✅ |
| DHT (Kademlia k-buckets, friend search, NAT hole punching, LAN discovery) | ✅ |
| Onion routing: relay, announce server, announce/search client, DHT key exchange | ✅ |
| net_crypto: cookies, handshake, lossless/lossy packets, retransmission, congestion control | ✅ |
| Friend requests, messages and actions, read receipts | ✅ |
| Name, status message, away/busy, typing notifications | ✅ |
| File transfers (pause/resume/cancel/seek, avatars) | ✅ |
| Custom lossless/lossy packets | ✅ |
| Profiles in toxcore/qTox savedata format, including encrypted `toxEsave` profiles | ✅ |
| TCP relays and proxies | ❌ not yet |
| Audio/video calls (ToxAV) | ❌ not yet |
| Conferences and group chats | ❌ not yet (their savedata sections are preserved) |

Without TCP relays, a friend must be reachable over UDP: directly, on the same LAN, or after NAT
hole punching. This covers most home networks, but not strict firewalls that block UDP.

### Compatibility

Every protocol layer is tested against c-toxcore **v0.2.23** over real UDP sockets (see
[Testing](#testing)): friend requests in both directions, messages, receipts, names, file transfers
both ways, plain and encrypted profiles loaded by each implementation. Toxide also joins the public
Tox network (bootstrap, DHT, onion announce) and exchanges messages with toxcore clients through it.

## Quick start

```csharp
using Toxide;

// Load the profile if we have one (qTox profiles work too; set SaveDataPassphrase if encrypted).
var options = new ToxOptions();
if (File.Exists("me.tox"))
{
    options.SaveDataType = ToxSaveDataType.ToxSave;
    options.SaveData = File.ReadAllBytes("me.tox");
}

using var tox = Tox.Create(options);
tox.Name = "Alice";
Console.WriteLine($"My Tox ID: {tox.Address}");

tox.FriendRequestReceived += (_, e) =>
{
    Console.WriteLine($"Request: {e.Message}");
    tox.AddFriendNoRequest(e.PublicKey);              // accept
};
tox.FriendMessageReceived += (_, e) =>
    Console.WriteLine($"{tox.GetFriendName(e.FriendNumber)}: {e.Message}");
tox.FriendConnectionStatusChanged += (_, e) =>
{
    if (e.Connection != ToxConnection.None)
        tox.SendMessage(e.FriendNumber, "Hi! I'm running on Toxide.");
};

// Join the network through one or more bootstrap nodes (list: https://nodes.tox.chat).
tox.Bootstrap("144.217.167.73", 33445, "7E5668E0EE09E19F320AD47902419331FFEE147BB3606769CFBE921A2A2FD34C");

// Add a friend by Tox ID.
tox.AddFriend("76-hex-character Tox ID of your friend", "Hello, it's Alice");

using var cts = new CancellationTokenSource();
await tox.RunAsync(cts.Token);                          // or call tox.Iterate() in your own loop

File.WriteAllBytes("me.tox", tox.GetSaveData());       // or GetSaveData("passphrase") to encrypt
```

A complete console client is in [`samples/EchoBot`](samples/EchoBot/Program.cs): it fetches the
public bootstrap node list, accepts friend requests and echoes messages.

### Driving the instance

* `RunAsync(token)` runs the protocol loop until cancelled, waking up as soon as packets arrive.
* Alternatively call `Iterate()` yourself every `IterationInterval` (≤ 50 ms), like `tox_iterate`.
* **All events are raised from inside `Iterate`/`RunAsync`, on that thread.** UI applications should
  marshal to their UI thread.
* Every public member is thread-safe (an internal lock); handlers may call back into the instance.
* Exceptions thrown while processing packets, timers or your handlers do not stop the instance: they
  are reported through the `InternalError` event.

### Friends and messages

| Method | toxcore equivalent |
|---|---|
| `AddFriend(address, message)` / `AddFriendNoRequest(publicKey)` | `tox_friend_add` / `tox_friend_add_norequest` |
| `DeleteFriend`, `FriendList`, `FindFriend`, `FriendExists` | `tox_friend_delete`, `tox_self_get_friend_list`, ... |
| `SendMessage(friend, text, type)` → message id, confirmed by `FriendReadReceipt` | `tox_friend_send_message` |
| `SetTyping`, `Name`, `StatusMessage`, `Status`, `NoSpam` | `tox_self_set_*` |
| `GetFriendName`, `GetFriendStatusMessage`, `GetFriendStatus`, `GetFriendConnectionStatus`, `GetFriendLastOnline` | `tox_friend_get_*` |
| `SendLosslessPacket` (ids 160-191), `SendLossyPacket` (200-254) | `tox_friend_send_lossless_packet`, ... |

Errors are reported with `ToxException`, whose `Code` (`ToxErrorCode`) mirrors toxcore's error enums.
Text is UTF-8 on the wire; limits are in bytes (`Tox.MaxMessageLength` = 1372, `Tox.MaxNameLength` = 128, ...).

### File transfers

```csharp
// Sending: offer the file, then serve chunks when asked.
uint file = tox.FileSend(friend, ToxFileKind.Data, (ulong)bytes.Length, "photo.jpg");
tox.FileChunkRequested += (_, e) =>
{
    if (e.Length > 0)   // Length == 0: the friend received everything
        tox.FileSendChunk(e.FriendNumber, e.FileNumber, e.Position, bytes.AsSpan((int)e.Position, e.Length));
};

// Receiving: accept (Resume) or refuse (Cancel), then collect chunks.
tox.FileReceiveRequested += (_, e) => tox.FileControl(e.FriendNumber, e.FileNumber, ToxFileControl.Resume);
tox.FileChunkReceived += (_, e) =>
{
    if (e.Data.Length == 0) { /* complete */ } else { output.Position = (long)e.Position; output.Write(e.Data); }
};
```

Avatars use `ToxFileKind.Avatar` with `Tox.Hash(image)` as file id, as qTox does.

### Profiles

`GetSaveData()` produces the same format as `tox_get_savedata`, so profiles move freely between Toxide,
qTox and other toxcore clients. Sections Toxide does not use (conferences, group chats) are kept and
written back unchanged. `ToxEncryptSave` reads and writes the `toxEsave` format used for encrypted
qTox profiles.

## Architecture

The library follows toxcore's layering; each layer only talks to the one below:

```
Tox (public API)
 └─ Messenger        friend list, requests, messages, presence, file transfers     Messenger/
     └─ FriendConnections   onion + DHT + net_crypto per friend, keep-alive          Messenger/
         ├─ OnionClient      announce ourselves, search friends, exchange DHT keys  Onion/
         ├─ NetCrypto        encrypted reliable sessions over UDP                   NetCrypto/
         └─ DhtNode          Kademlia DHT, friend IP search, NAT punching           Dht/
             ├─ OnionRelay, OnionAnnounceServer   (services every node provides)    Onion/
             └─ UdpTransport, PacketDispatcher                                      Network/
                 └─ ManagedCryptoCore   X25519 + XSalsa20-Poly1305 (NaCl crypto_box)  Crypto/
```

Protocol state is single-threaded by design (everything runs inside `Iterate`), mirroring toxcore.
Every component takes a `TimeProvider`, which makes the whole stack testable on a virtual network
with a virtual clock.

## Testing

```bash
dotnet test
```

The suite includes unit tests per layer and whole-stack scenarios on an in-memory network with a
manual clock (minutes of protocol time run in milliseconds, packet loss included).

Interop tests run Toxide against the real c-toxcore over UDP on localhost. They need a small C
harness built against c-toxcore (requires git, a C compiler and libsodium):

```bash
scripts/build-toxpeer.sh            # clones c-toxcore v0.2.23 into .toxpeer/ and builds it
export TOXIDE_TOXPEER=$PWD/.toxpeer/toxpeer
dotnet test
```

Without `TOXIDE_TOXPEER` the interop tests are skipped.

## License

Toxide is a port of the Tox protocol as implemented by c-toxcore, which is licensed under the
GNU GPL v3 or later; Toxide is distributed under the same license, [GPL-3.0-or-later](LICENSE).
