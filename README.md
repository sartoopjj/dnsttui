# dnsttui

A DNS tunnel server with integrated Shadowsocks 2022 and a web management panel.

Built on top of [dnstt](https://www.bamsoftware.com/software/dnstt/), dnsttui wraps the DNS tunnel with a multi-user Shadowsocks 2022 proxy and a simple web UI for managing users, monitoring traffic, and configuring everything from a browser.

## How It Works

```
                        ┌────────────┐
  Client ──DNS query──▶ │  dnsttui   │
         ◀─DNS reply──  │            │
                        │  DNS Tunnel│──▶ Shadowsocks 2022 ──▶ Internet
                        │  + Panel   │
                        └────────────┘
                            :8080 (web panel)
```

1. A DNS tunnel (dnstt) listens for encoded DNS queries on a UDP port
2. Traffic is decrypted (Noise NK) and forwarded to a local Shadowsocks 2022 server
3. Shadowsocks handles multi-user authentication and proxies traffic to the internet
4. A web panel lets you manage users, view traffic, and configure settings

## Features

- **DNS Tunnel** — Encrypts traffic inside DNS queries (works even behind restrictive firewalls)
- **Shadowsocks 2022** — Modern `2022-blake3-aes-128-gcm` with per-user keys
- **Web Panel** — Manage users, traffic limits, expiration, and server settings
- **Diagnostics** — Real-time server status, active connections, and traffic stats
- **CLI Config** — Manage all settings from the command line (`dnsttui config`)
- **Auto Key Generation** — Noise keypair and SS server key are generated on first run
- **Secure Defaults** — Random admin credentials and panel path on first run
- **Single Binary** — No dependencies, no CGO, runs anywhere
- **Simple Install** — One-command install with systemd service

## DNS Records Setup

You need **two DNS records** on your domain. Suppose your server IP is `203.0.113.10` and you want to use `example.com`:

### 1. A Record for the NS server

| Type | Name | Value |
|------|------|-------|
| A | `ns.example.com` | `203.0.113.10` |

This points a hostname to your server IP.

### 2. NS Record for the tunnel subdomain

| Type | Name | Value |
|------|------|-------|
| NS | `t.example.com` | `ns.example.com` |

This delegates all DNS queries for `t.example.com` (and its subdomains) to your server.

### Verify

After DNS propagation (may take a few minutes), verify with:

```bash
dig t.example.com NS
```

You should see `ns.example.com` in the answer. Then in the panel settings, set:

- **DNSTT Domain** = `t.example.com`
- **DNSTT UDP Address** = `:5300` (or `0.0.0.0:53` if you can bind port 53)

> **Note:** The tunnel server needs to receive packets on external port 53. Running on `:53` directly requires root. It's better to listen on an unprivileged port (`:5300`) and port-forward 53 to it.
>
> Replace `eth0` with your actual network interface name (check with `ip a`):
> ```bash
> sudo iptables -I INPUT -p udp --dport 5300 -j ACCEPT
> sudo iptables -t nat -I PREROUTING -i eth0 -p udp --dport 53 -j REDIRECT --to-ports 5300
> sudo ip6tables -I INPUT -p udp --dport 5300 -j ACCEPT
> sudo ip6tables -t nat -I PREROUTING -i eth0 -p udp --dport 53 -j REDIRECT --to-ports 5300
> ```
>
> To make these rules persistent across reboots:
> ```bash
> sudo apt install iptables-persistent   # Debian/Ubuntu
> sudo netfilter-persistent save
> ```

### (Optional) Panel domain

If you want HTTPS on the web panel, also add an A record for it:

| Type | Name | Value |
|------|------|-------|
| A | `panel.example.com` | `203.0.113.10` |

Then set **Panel Domain** = `panel.example.com` and an **ACME Email** in the panel settings. TLS will be provisioned automatically via Let's Encrypt.

## Install

### One-Command Install (Linux)

```bash
bash <(curl -Ls https://raw.githubusercontent.com/sartoopjj/dnsttui/main/install.sh)
```

This will:
- Download the latest binary to `/usr/local/bin/dnsttui`
- Create a data directory at `/opt/dnsttui/`
- Ask for admin username, password, panel port, and optional domains
- Initialize the config and set up a systemd service

After install, the panel is available at the URL shown at the end of installation.

### Update

```bash
bash <(curl -Ls https://raw.githubusercontent.com/sartoopjj/dnsttui/main/install.sh) update
```

### Uninstall

```bash
bash <(curl -Ls https://raw.githubusercontent.com/sartoopjj/dnsttui/main/install.sh) uninstall
```

### Build From Source

```bash
git clone https://github.com/sartoopjj/dnsttui.git
cd dnsttui
make all
```

Requires Go 1.24+ and [templ](https://templ.guide/).

### Manual Run

```bash
./dnsttui serve --panel-addr :8080 --udp :5300
```

On first run without prior configuration, random admin credentials and a random panel path are generated and printed to the console. Save them — they won't be shown again.

You can also pre-initialize config before starting:

```bash
./dnsttui config init --admin-user myuser --admin-pass mypass --base-path /panel
./dnsttui serve --panel-addr :8080 --udp :5300
```

#### Serve Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--db` | SQLite database path | `dnsttui.db` |
| `--panel-addr` | Panel listen address | `:8080` (from DB) |
| `--udp` | DNS tunnel UDP address | from DB config |
| `--domain` | Panel domain for ACME TLS | from DB config |
| `--mtu` | Max DNS response size | from DB config |

## CLI Configuration

All settings can be managed from the command line with `dnsttui config`:

```bash
# Show current config
dnsttui config show

# Initialize config (first time only)
dnsttui config init --admin-user admin --admin-pass secret

# Update settings
dnsttui config set --admin-pass newsecret
dnsttui config set --dnstt-domain t.example.com --dnstt-udp :5300
dnsttui config set --panel-domain panel.example.com --acme-email you@example.com
```

#### Config Set Flags

| Flag | Description |
|------|-------------|
| `--admin-user` | Admin username |
| `--admin-pass` | Admin password (bcrypt hashed automatically) |
| `--base-path` | Panel base path (e.g. `/mypath`) |
| `--panel-domain` | Panel domain for ACME TLS |
| `--acme-email` | ACME email for TLS certificates |
| `--dnstt-domain` | DNS tunnel domain |
| `--dnstt-udp` | DNS tunnel UDP listen address |
| `--dnstt-mtu` | DNS tunnel MTU |
| `--ss-listen` | Shadowsocks listen address |
| `--ss-port` | Shadowsocks port |
| `--dns-resolver` | DNS resolver address for clients |
| `--dns-resolver-port` | DNS resolver port for clients |

## Quick Start

1. Install dnsttui on your server
2. Open the panel at the URL shown after installation, log in with your credentials
3. Go to **Settings** — set your DNSTT Domain and UDP address
4. Go to **Users** — add a Shadowsocks user
5. Click the config icon on the user to get a MahsaNG/v2ray client config
6. Set up DNS records as described above
7. Connect with your client

## Credits

- [dnstt](https://www.bamsoftware.com/software/dnstt/) by David Fifield
- [sing-shadowsocks](https://github.com/sagernet/sing-shadowsocks) for SS2022 implementation