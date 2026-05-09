# netscanner

A network scanner that knows it's a network scanner and is at peace with that.

You point it at a subnet. It connects to every host, pretends to be a legitimate
protocol client, takes notes, and leaves. The pcap file it generates is, frankly,
more organized than most people's inboxes.

**Supported protocols:** Modbus (the one your PLC uses). More as the community
gets around to it — see [Community Plugins](#community-plugins).

---

## Quick start

```bash
# The one you actually want:
python3 netscanner.py 10.0.0.0/24 --protocol modbus

# "I forgot what protocols are installed"
python3 netscanner.py --list-protocols

# The interactive experience (TTY required, patience optional)
python3 netscanner.py 10.0.0.0/24

# The full paranoia package
python3 netscanner.py 10.0.0.0/24 --protocol modbus \
    --pcap-dir ./evidence --output results.csv --threads 50
```

---

## Installed plugins

| Plugin | Port | Notes |
|--------|------|-------|
| `modbus` | 502 | FC3 (holding registers) with FC1 (coil read) fallback; tests unit IDs 0 and 1 |

---

## Output

Terminal output, color-coded when stdout is a TTY:

```
[10.0.0.1]            OPEN                    unit_id=0  fc=3  register_value=0x6400  45ms
[10.0.0.2]            OPEN                    unit_id=1  fc=1  register_value=0x01    52ms
[10.0.0.3]            REFUSED                 connection refused  2ms
[10.0.0.4]            TIMEOUT_CONNECT         no response to SYN  2001ms
[10.0.0.5]            NO_MODBUS               unexpected response  12ms  (probably HTTP)
[10.0.0.6]            ZERO_WINDOW             TCP ZeroWindow on send  3ms
```

Every result gets a status. `OPEN` means it talked back correctly. `NO_MODBUS` means
something answered but pretended not to understand. We've all been there.

**CSV** (`--output results.csv`): ip, status, latency_ms, detail, plus one column per
protocol-specific field found across all results. The header writes itself.

**pcap** (`--pcap-dir captures/`): one `.pcap` per host plus a combined
`scan_TIMESTAMP.pcap`. Open in Wireshark. Full TCP/IP headers, correct checksums,
synthesized in userspace — no root required, no raw socket privileges needed.

---

## Status codes

| Status | Meaning |
|--------|---------|
| `OPEN` | Device answered the protocol correctly |
| `REFUSED` | TCP RST — port closed, nobody home |
| `TIMEOUT_CONNECT` | No response to SYN — host unreachable or filtered |
| `TIMEOUT_RESPONSE` | Connected fine, then went silent |
| `ZERO_WINDOW` | Connected, then froze the TCP receive window |
| `CLOSED_IMMEDIATELY` | Said hi and hung up before we asked anything |
| `NO_MODBUS` | Something answered, but it wasn't speaking Modbus |

---

## CLI reference

```
usage: netscanner.py [-h] [--file FILE] [--protocol NAME] [--list-protocols]
                     [--threads N] [--connect-timeout S] [--response-timeout S]
                     [--port PORT] [--output FILE] [--pcap-dir DIR]
                     [targets ...]

positional arguments:
  targets               IPs and/or CIDR ranges (e.g. 10.0.0.1 10.0.0.0/24)

options:
  --file FILE, -f FILE  text file with one IP or CIDR per line
  --protocol NAME       protocol plugin to use (see --list-protocols)
  --list-protocols      list available protocol plugins and exit
  --threads N           concurrent threads (default: 20)
  --connect-timeout S   TCP connect timeout in seconds (default: 2.0)
  --response-timeout S  protocol response timeout in seconds (default: 3.0)
  --port PORT           override the plugin's default port
  --output FILE         write CSV results to FILE
  --pcap-dir DIR        write per-host and combined .pcap captures to DIR
                        (created if it does not exist)
```

---

## Plugins

All plugins live in **[netscanner-plugins](https://github.com/fuhdan/netscanner-plugins)**
and are automatically synced here. To contribute a plugin, open a PR there — not here.

### Wanted protocols

| Protocol | Port |
|----------|------|
| OPC-UA | 4840 |
| BACnet/IP | 47808 |
| DNP3 | 20000 |
| EtherNet/IP | 44818 |
| S7comm | 102 |

If you want one, open an issue on netscanner-plugins.

---

## Writing a plugin

Create `plugins/yourprotocol.py`. Subclass `ProtocolPlugin`. Set `name` and
`default_port`. Implement `probe()`. Drop the file in `plugins/`. Done — no
registration step, no config, no build. It just appears in `--list-protocols`.

```python
from netscanner import ProtocolPlugin, ScanResult, STATUS_OPEN

class BannerPlugin(ProtocolPlugin):
    name = "banner"
    default_port = 80

    def probe(self, sock, ip, cfg, pcap_writers):
        sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        data = sock.recv(4096)
        return [ScanResult(ip=ip, status=STATUS_OPEN,
                           extra={"banner": data[:80].decode(errors="replace")})]
```

See `docs/plugins.md` for the full contract: what the framework guarantees before
`probe()` is called, how to write pcap frames Wireshark will understand, how to
handle ZeroWindow and timeouts, and a complete real-world example in `plugins/modbus.py`.

---

## Requirements

- Python 3.9+ — stdlib only, zero external dependencies
- No root access required (pcap is synthesized in userspace via regular TCP sockets)
- Works on Linux, macOS, probably Windows (untested, patches welcome)

---

## Tests

```bash
python3 -m pytest tests/
# 78 tests. They all pass. We checked.
```

---

## Contributing

Bug reports, new plugins, and pull requests are welcome. If you are about to open
an issue saying "it doesn't work on my Siemens S7", please include the pcap.
That's what the pcap is for.
