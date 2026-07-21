# Web Tether

> Create and connect to WebSocket relays to expose or access TCP services securely.

**Web Tether** is a lightweight CLI, built on [Deno](https://deno.com/), that tunnels arbitrary TCP
traffic over a single WebSocket connection. A central **relay** acts as a meeting point, and
**clients** connect to it to either expose local services to the network or reach services exposed by
other clients — all through one outbound WebSocket, with no need to open inbound ports on the client
side.

On top of raw port forwarding, Web Tether can also run a built-in **SOCKS4/5 proxy**, so you can route
proxy traffic across the relay either statically (everything to one remote service) or dynamically
(per-destination routing rules).

## Features

- **WebSocket relay** — a single WebSocket endpoint bridges TCP connections between authorized clients.
- **Local & remote port forwarding**
  - `--socket-bind` — expose a local TCP listener as a named service on the relay.
  - `--socket-connect` — open a local listener that forwards connections to a remote service.
- **Built-in SOCKS4/5 proxy**
  - `--proxy-bind` — serve SOCKS requests arriving from the relay.
  - `--proxy-connect-static` — run a local SOCKS proxy that sends all traffic to one remote service.
  - `--proxy-connect-dynamic` — run a local SOCKS proxy that routes traffic per-destination using a
    hot-reloadable mapping file.
- **Two authentication modes**
  - **Identity** — public/private key pairs (ECDH) for both relay and clients.
  - **Credentials** — salted, PBKDF2-SHA512 hashed passkeys stored on the relay.
- **Fine-grained permissions** — per-client `bind` / `connect` rules defined in a YAML/JSON file that
  the relay watches and reloads on change.
- **Cross-platform single binary** — precompiled executables for Linux, macOS, and Windows
  (amd64 / aarch64), with no runtime dependencies.

## Installation

### Download a prebuilt binary

Grab the executable for your platform from the
[Releases page](https://github.com/Menecats/web-tether/releases):

| Platform | File |
| --- | --- |
| Linux (x86_64) | `web-tether_linux_amd64` |
| Linux (aarch64) | `web-tether_linux_aarch64` |
| macOS (Intel) | `web-tether_darwin_amd64` |
| macOS (Apple Silicon) | `web-tether_darwin_aarch64` |
| Windows (x86_64) | `web-tether_win_amd64.exe` |
| Windows (aarch64) | `web-tether_win_aarch64.exe` |

On Linux/macOS, mark the file executable and (optionally) put it on your `PATH`:

```shell
chmod +x web-tether_linux_amd64
sudo mv web-tether_linux_amd64 /usr/local/bin/web-tether
web-tether --help
```

### Run from source

Web Tether is a Deno project. Deno **2.x** is required (tested with **2.9**).

```shell
git clone https://github.com/Menecats/web-tether.git
cd web-tether

# Run the CLI directly from source
deno run -A ./src/cli/cli.ts --help
```

### Build your own binaries

The repository ships with [Deno tasks](https://docs.deno.com/runtime/reference/cli/task/) to bundle and
compile the CLI:

```shell
# Bundle the CLI into dist/web-tether.js
deno task bundle

# Bundle and compile standalone binaries for every target into dist/
deno task compile

# ...or compile a single target, e.g. Windows x86_64
deno task compile:win:amd64
```

## Quickstart

The following walkthrough sets up a relay and connects a client that exposes a local SSH server
(port 22) to other clients on the relay, using identity-based authentication.

### 1. Generate identities

Create a key pair for the relay and one for the client. Each command writes a private key file and a
matching `.pub` public key file.

```shell
web-tether generate-identity --identity-file relay-identity
web-tether generate-identity --identity-file client-identity
```

### 2. Configure client permissions

Create a `clients.yml` file describing who may connect and what they are allowed to do. Paste the
**client's public key** (contents of `client-identity.pub`) into the `auth` field:

```yaml
version: 1
clients:
  - alias: my-client
    auth: identity:<contents-of-client-identity.pub>
    permissions:
      - "bind|remote-ssh"
      - "connect|*"
```

Permission entries follow the `<action>|<service-pattern>` format, where `<action>` is `bind` or
`connect` and the pattern supports `*` wildcards.

### 3. Start the relay

```shell
web-tether relay \
    --clients clients.yml \
    --identity relay-identity
```

By default the relay listens on `0.0.0.0:3000` (configurable with `--host` / `--port`). It watches the
clients file and reloads permissions automatically when it changes.

### 4. Connect a client

Expose the local SSH server as the `remote-ssh` service on the relay:

```shell
web-tether connect \
    --auth-identity-private-key client-identity \
    --auth-identity-relay-public-key relay-identity.pub \
    --socket-bind remote-ssh@127.0.0.1:22 \
    ws://localhost:3000/relay
```

Another client can then reach that service by forwarding a local port to it:

```shell
web-tether connect \
    --auth-identity-private-key client-identity \
    --auth-identity-relay-public-key relay-identity.pub \
    --socket-connect 0.0.0.0:1022@remote-ssh \
    ws://localhost:3000/relay
```

Connecting to `localhost:1022` now tunnels through the relay to the first client's SSH server.

### Using credentials instead of identities

If you prefer password-style authentication, generate a credential record and store it on the relay:

```shell
web-tether generate-credentials --identifier my-user
# -> credentials:my-user:<salt>|<hash>
```

Add the printed line to a client's `auth` field in `clients.yml`, then connect with
`--auth-credentials-identifier my-user` (the CLI will securely prompt for the passkey).

## Documentation

Every command and option is documented directly in the CLI's built-in help. Run any command with
`--help` to see its full reference:

```shell
web-tether --help
web-tether connect --help
web-tether relay --help
```

## License

This project is licensed under the **GNU General Public License v3.0**. See [LICENSE](./LICENSE) for
details.

Copyright © 2026 Davide Menegatti.
