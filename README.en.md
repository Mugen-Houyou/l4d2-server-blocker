# L4D2 Server Blocker

A program that intercepts unwanted server connections from Left 4 Dead 2's matchmaker at the kernel level, instantly returning to the main title UI.

<a href="https://www.youtube.com/watch?v=X6DU8O_8J6Q"><img src="https://img.youtube.com/vi/X6DU8O_8J6Q/maxresdefault.jpg" width="360"></a>

[Demo video](https://www.youtube.com/watch?v=X6DU8O_8J6Q)

## Problem

L4D2's matchmaker does not distinguish between official and private servers. Asking a private server operator to ban you (a "self-ban") offers no guarantee, and blocking them via Windows Firewall causes 10 retry attempts, wasting time.

This meant that every time you joined a match, you had to open the console with \`, visually check whether the IP address belongs to an unwanted private server, and if so, type `disconnect` or click leave — a tedious process repeated over and over.

## Solution

This program solves the above problem by making the L4D2 client immediately return to the main title UI when it attempts to connect to a specific private server.

**This program does not modify or tamper with the L4D2 game itself — it intercepts packets destined for specific servers at the Windows network stack level and sends back a response on their behalf.** It uses the [WinDivert](https://reqrypt.org/windivert.html) kernel driver to capture outbound UDP packets to blocked servers and injects a response mimicking the Source engine protocol, causing the L4D2 client to immediately give up the connection. See "How It Works" below for details.

```
Client ──A2S_GETCHALLENGE──▶ Blocked Server
         ▲ (WinDivert intercept)
         │
         └─ S2C_CHALLENGE    → auth protocol = 0 (invalid) → immediate Disconnect()
```

## Requirements

- Windows 10/11 (64-bit)
- Administrator privileges

## Usage

1. Add the IP addresses and ports of the private servers you want to avoid to `blocked_servers.json`.

- You can find the server's IP address and port in the in-game console (\` key).

<img src="docs/console-ip.png" width="480">

- See the example below for reference. Wildcards are also supported.

```json
[
    "12.34.56.78:270??",
    "12.34.56.78:270*",
    "12.34.56.*:270*",
    "12.34.56.78:27012"
]
```

2. Double-click `server_blocker.exe` and run it with administrator privileges. Note that `server_blocker.exe` and `blocked_servers.json` must be in the same folder.


3. Launch L4D2 and play as usual. When a blocked server is matched, you will instantly return to the main UI.

### Wildcard Patterns

`blocked_servers.json` supports wildcard patterns as shown below. `*` matches any number of characters, and `?` matches exactly one character.

| Pattern | Meaning | Example Match |
|---|---|---|
| `12.34.56.78:27015` | Exact match | `12.34.56.78:27015` |
| `12.34.56.78:270??` | `?` = any single character | `27000`–`27099` |
| `12.34.56.78:27*` | `*` = any string | `27`, `270`, `27014`, ... |
| `10.0.0.*:27015` | Also works for IPs | `10.0.0.0`–`10.0.0.255` |

## Scope

> The sections below are technical details, provided for reference only.

This applies to **all Windows outbound UDP**, not just L4D2. WinDivert's NETWORK layer does not support per-process (PID) filtering. If per-process restriction is needed, moving to the SOCKET layer could be considered.

## How It Works

1. Load patterns from `blocked_servers.json`
2. Build a WinDivert filter based on IPs to capture outbound UDP at the kernel level
3. Match captured packets' `IP:Port` against patterns using `fnmatch`
4. If no match, pass the original packet through (re-inject)
5. If matched and the packet is a Source engine `A2S_GETCHALLENGE` (`0x71`):
   - Parse the challenge value from the `"connect0xXXXXXXXX"` string in the payload
   - Construct a forged `S2C_CHALLENGE` response (invalid auth protocol = 0)
   - Swap src↔dst in IP/UDP headers and inject inbound via WinDivert
   - Drop the original outbound packet
6. All other matched packets are silently dropped

## Why It Blocks Instantly

### Limitations of Windows Firewall (DROP)

Windows Firewall is the simplest way to block connections to unwanted servers.

However, when you block a specific IP with Windows Firewall, outbound packets are simply **discarded**. Since no response comes back from the server, the L4D2 client cannot tell whether the connection failed or whether it should keep waiting (e.g., the server is changing maps mid-connection). As a result, the client wastes time repeating **10 retry attempts**.

```
Client ──A2S_GETCHALLENGE──▶ (Firewall DROP) ──✕
         ... timeout ...
Client ──A2S_GETCHALLENGE──▶ (Firewall DROP) ──✕    ← repeated 10 times
         ... timeout ...
"Connection failed after 10 retries."
```

### Source Engine Connection Handshake

L4D2 (Source engine) server connections begin with a UDP-based connectionless handshake:

1. **Client → Server**: Sends `A2S_GETCHALLENGE` (`FF FF FF FF 71`). The payload contains a `retryChallenge` value in the format `"connect0xXXXXXXXX"`
2. **Server → Client**: Responds with `S2C_CHALLENGE` (`FF FF FF FF 41`). Echoes the client's `retryChallenge`, and includes a server-side challenge and **auth protocol**
3. The client checks the auth protocol value. The only valid value is `PROTOCOL_STEAM = 3`; any other value triggers `Disconnect()` and immediately aborts the connection

### How This Tool Blocks

This tool responds in place of the server at step 2. When WinDivert intercepts an `A2S_GETCHALLENGE` outbound packet:

1. Parse the `retryChallenge` value from the original packet's payload (8-digit hex after `"connect0x"` → 4-byte little-endian integer).
2. Construct a forged `S2C_CHALLENGE` packet:

```
FF FF FF FF 41              ← connectionless header + S2C_CHALLENGE
[retryChallenge:4]          ← echo the client's challenge
[server_challenge:4]        ← arbitrary value (0x04030201)
[auth_protocol:4 = 0]      ← key: 0 is an invalid auth protocol
```

3. Swap src↔dst in the IP/UDP headers to make it appear as a response from the server, then inject it **inbound** via WinDivert
4. The original outbound packet is dropped and never reaches the server

The client reads `auth_protocol = 0`, sees it is not `PROTOCOL_STEAM(3)`, and immediately calls `Disconnect()`. The connection is terminated **instantly** with no timeout or retries, and the client returns to the main title UI without any message.

## Running with Python or Building from Source

### Running with Python

- Requires Python 3.10+
- Install the library with `pip install pydivert`, then run:

```bash
python server_blocker.py
```

### Building a Portable EXE

```bash
pip install pyinstaller pydivert
pyinstaller --onefile --uac-admin --console \
  --add-data "<site-packages>/pydivert/windivert_dll/WinDivert64.dll;pydivert/windivert_dll" \
  --add-data "<site-packages>/pydivert/windivert_dll/WinDivert64.sys;pydivert/windivert_dll" \
  --add-binary "<python-env>/Library/bin/ffi.dll;." \
  server_blocker.py
```

The built `server_blocker.exe` runs standalone without Python. A UAC manifest is embedded, so it automatically requests administrator privileges when double-clicked.


## License

AGPLv3
