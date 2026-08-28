# VeilRoot Name System (VNS)

Copyright (c) 2026 The VeilRoot Project  
Copyright (c) 2014-2022 The Monero Project (original codebase)  
Portions Copyright (c) 2012-2013 The Cryptonote developers.

## Table of Contents

- [Introduction](#introduction)
- [About this project](#about-this-project)
- [Development resources](#development-resources)
- [Vulnerability response](#vulnerability-response)
- [License](#license)
- [Contributing](#contributing)
- [Supporting the project](#supporting-the-project)
- [Scheduled software upgrades](#scheduled-software-upgrades)
- [Compiling VNS from source](#compiling-vns-from-source)
  - [Dependencies](#dependencies)
  - [Build instructions](#build-instructions)
  - [Cross-compiling for Windows (mingw)](#cross-compiling-for-windows-mingw)
  - [Troubleshooting common build issues](#troubleshooting-common-build-issues)
- [Using VNS](#using-vns)
  - [Running the daemon (vnsd)](#running-the-daemon-vnsd)
  - [Wallet commands](#wallet-commands)
  - [Resolution API](#resolution-api)
  - [End‑to‑end test](#endtoend-test)
  - [Manual resolver (HTML page)](#manual-resolver-html-page)
  - [Browser extension](#browser-extension)
- [Internationalization](#internationalization)
- [Using Tor](#using-tor)
- [Pruning](#pruning)
- [Debugging](#debugging)
- [Known issues](#known-issues)

---

## Introduction

VeilRoot Name System (VNS) is a private, secure, and decentralized alternative to ICANN's Domain Name System (DNS). It combines a privacy-focused blockchain (forked from Monero) with the NOSTR protocol to deliver anonymous domain registration, resolution, and management – all without exposing personal data or relying on central authorities.

**Privacy:** VNS uses Monero's cryptographic primitives – ring signatures, stealth addresses, Bulletproofs, and Dandelion++ – to ensure that domain registrations, transfers, and updates are untraceable and unlinkable.

**Security:** The blockchain is secured by a distributed peer-to-peer consensus network using the RandomX proof-of-work, making it ASIC-resistant and accessible to commodity hardware.

**Decentralization:** No central authority controls the namespace. Anyone can register a domain, create new extensions (e.g., `..free`, `..art`), and operate a Nostr relay to serve domain data.

**Dynamic Health Mechanism:** Domains remain valid only while their associated Nostr relay continuously publishes "heartbeat" proofs. This prevents squatting without artificial renewal fees.

**Double-Dot Namespace:** Domains follow the format `[label]..[extension]` (e.g., `myblog..free`), providing a flexible, user-defined namespace that escapes ICANN's hierarchical control.

**Tiered Fee Structure:** Registration fees range from **0.1 VNS** (tier 0) to **10,000 VNS** (tier 5), scaling ×10 per tier, and are permanently burned.

## About this project

This is the core implementation of VeilRoot Name System, forked from Monero (v0.18.5.0). It includes a custom blockchain with domain-specific opcodes, integration with Nostr relays for service descriptors and heartbeats, and a command-line wallet and daemon.

For a detailed technical description of the project, architecture, namespace system, resolution mechanism, privacy model, governance, and implementation roadmap, see the [VeilRoot Name System White Paper](VEILROOT-WHITEPAPER.md).

The repository is the main development branch; we encourage contributors to join the discussion on NOSTR and to submit pull requests.

## Development resources

- GitHub: https://github.com/ailerov/veilroot.git
- NOSTR: *npub1ex2mt0e7rfk7t0av77tfqh0zehp7zm994stqaxjj93gqn27r7m3qgkz0jy*

## Vulnerability response

We follow the [Monero Vulnerability Response Process](https://github.com/monero-project/meta/blob/master/VULNERABILITY_RESPONSE_PROCESS.md) for responsible disclosure. Please report security issues via email to [mail-k8qqjpm7vaml@neirmail.com]

## License

See [LICENSE](LICENSE) – same as Monero (BSD 3‑clause).

## Contributing

See [CONTRIBUTING](docs/CONTRIBUTING.md) for guidelines. All contributions are welcome, especially those related to resolver implementations, Nostr integration, and wallet tooling.

## Supporting the project

VNS is a community‑sponsored project. Donations in XMR can be sent to the donation address below. You can also support by running a public node or contributing code.

The donation address (XMR) is:  
`865ikSGgu5MGTi74aB1ttEARSPZrbCkXmcoranGgTsZQ3WmifHCSBoCR3UUdi6kW6LCuDdP62bv7TBkKoAK2y9uY3tp6245`  
*(for VNS donations just use the [donate] command in your VeilRoot wallet - your donation will be sent to VeilRoot development treasury)*

## Scheduled software upgrades

VNS uses a hard-fork schedule similar to Monero's, but upgrades will be announced on the project website and IRC. The current version is v0.18.5.0 (fork point). Future upgrades may adjust fee tiers, health parameters, or introduce new features.

## Compiling VNS from source

### Dependencies

The dependencies are identical to Monero's, except that **libsecp256k1** is now required (for BIP340 Schnorr signatures used in Nostr). The build system includes it as a submodule.

| Dep          | Min. version  | Vendored | Debian/Ubuntu pkg    | Arch pkg     | Void pkg           | Fedora pkg          | Optional | Purpose         |
| ------------ | ------------- | -------- | -------------------- | ------------ | ------------------ | ------------------- | -------- | --------------- |
| GCC          | 5             | NO       | `build-essential`    | `base-devel` | `base-devel`       | `gcc`               | NO       |                 |
| CMake        | 3.5           | NO       | `cmake`              | `cmake`      | `cmake`            | `cmake`             | NO       |                 |
| pkg-config   | any           | NO       | `pkg-config`         | `base-devel` | `base-devel`       | `pkgconf`           | NO       |                 |
| Boost        | 1.66          | NO       | `libboost-all-dev`   | `boost`      | `boost-devel`      | `boost-devel`       | NO       | C++ libraries   |
| OpenSSL      | basically any | NO       | `libssl-dev`         | `openssl`    | `openssl-devel`    | `openssl-devel`     | NO       | sha256 sum      |
| libzmq       | 4.2.0         | NO       | `libzmq3-dev`        | `zeromq`     | `zeromq-devel`     | `zeromq-devel`      | NO       | ZeroMQ library  |
| OpenPGM      | ?             | NO       | `libpgm-dev`         | `libpgm`     |                    | `openpgm-devel`     | NO       | For ZeroMQ      |
| libnorm[2]   | ?             | NO       | `libnorm-dev`        |              |                    |                     | YES      | For ZeroMQ      |
| libunbound   | 1.4.16        | YES      | `libunbound-dev`     | `unbound`    | `unbound-devel`    | `unbound-devel`     | NO       | DNS resolver    |
| libsodium    | ?             | NO       | `libsodium-dev`      | `libsodium`  | `libsodium-devel`  | `libsodium-devel`   | NO       | cryptography    |
| libunwind    | any           | NO       | `libunwind8-dev`     | `libunwind`  | `libunwind-devel`  | `libunwind-devel`   | YES      | Stack traces    |
| liblzma      | any           | NO       | `liblzma-dev`        | `xz`         | `liblzma-devel`    | `xz-devel`          | YES      | For libunwind   |
| libreadline  | 6.3.0         | NO       | `libreadline6-dev`   | `readline`   | `readline-devel`   | `readline-devel`    | YES      | Input editing   |
| expat        | 1.1           | NO       | `libexpat1-dev`      | `expat`      | `expat-devel`      | `expat-devel`       | YES      | XML parsing     |
| GTest        | 1.5           | YES      | `libgtest-dev`[1]    | `gtest`      | `gtest-devel`      | `gtest-devel`       | YES      | Test suite      |
| ccache       | any           | NO       | `ccache`             | `ccache`     | `ccache`           | `ccache`            | YES      | Compil. cache   |
| Doxygen      | any           | NO       | `doxygen`            | `doxygen`    | `doxygen`          | `doxygen`           | YES      | Documentation   |
| Graphviz     | any           | NO       | `graphviz`           | `graphviz`   | `graphviz`         | `graphviz`          | YES      | Documentation   |
| lrelease     | ?             | NO       | `qttools5-dev-tools` | `qt5-tools`  | `qt5-tools`        | `qt5-linguist`      | YES      | Translations    |
| libhidapi    | ?             | NO       | `libhidapi-dev`      | `hidapi`     | `hidapi-devel`     | `hidapi-devel`      | YES      | Hardware wallet |
| libusb       | ?             | NO       | `libusb-1.0-0-dev`   | `libusb`     | `libusb-devel`     | `libusbx-devel`     | YES      | Hardware wallet |
| libprotobuf  | ?             | NO       | `libprotobuf-dev`    | `protobuf`   | `protobuf-devel`   | `protobuf-devel`    | YES      | Hardware wallet |
| protoc       | ?             | NO       | `protobuf-compiler`  | `protobuf`   | `protobuf`         | `protobuf-compiler` | YES      | Hardware wallet |
| libudev      | ?             | NO       | `libudev-dev`        | `systemd`    | `eudev-libudev-devel` | `systemd-devel`  | YES      | Hardware wallet |
| **libsecp256k1** | latest   | YES      | `libsecp256k1-dev`   | `libsecp256k1`| `libsecp256k1-devel` | `libsecp256k1-devel` | NO       | Nostr signatures |

[1] On Debian/Ubuntu `libgtest-dev` only includes sources and headers. You must build the library binary manually:

```
sudo apt-get install libgtest-dev
cd /usr/src/gtest
sudo cmake .
sudo make
```

Then, on Debian:
```
sudo mv libg* /usr/lib/
```
On Ubuntu:
```
sudo mv lib/libg* /usr/lib/
```

[2] libnorm-dev is needed if your zmq library was built with libnorm, and not needed otherwise.

Install all dependencies at once on Debian/Ubuntu (including libsecp256k1 if available):

```
sudo apt update && sudo apt install build-essential cmake pkg-config libssl-dev libzmq3-dev libunbound-dev libsodium-dev libunwind8-dev liblzma-dev libreadline6-dev libexpat1-dev libpgm-dev qttools5-dev-tools libhidapi-dev libusb-1.0-0-dev libprotobuf-dev protobuf-compiler libudev-dev libboost-chrono-dev libboost-date-time-dev libboost-filesystem-dev libboost-locale-dev libboost-program-options-dev libboost-regex-dev libboost-serialization-dev libboost-system-dev libboost-thread-dev python3 ccache doxygen graphviz libsecp256k1-dev
```

If `libsecp256k1-dev` is not available, the vendored copy will be used automatically.

### Build instructions

1. Clone the repository (with submodules):
   ```bash
   git clone --recursive https://github.com/veilroot-project/veilroot
   cd veilroot
   ```

2. Build:
   ```bash
   make
   ```

   For a release build with optimizations:
   ```bash
   make release
   ```

   For a static build (recommended for distribution):
   ```bash
   make release-static
   ```

3. The binaries (`vnsd`, `vns-wallet-cli`, `vns-wallet-rpc`) will be in `build/release/bin`.

### Cross‑compiling for Windows (mingw) (WSL / Linux host)

Veilroot uses a **depends** system to build all required libraries and a
cross‑compilation toolchain. The following steps work on WSL (Ubuntu) or
a native Linux host.

1. **Install cross‑compilation packages** (Ubuntu example):
   ```bash
   sudo apt update && sudo apt install -y g++-mingw-w64-x86-64
   ```

2. **Build the cross‑compilation toolchain and dependencies**:
   ```bash
   make -C contrib/depends HOST=x86_64-w64-mingw32 -j$(nproc)
   ```
   This creates `contrib/depends/x86_64-w64-mingw32/share/toolchain.cmake`
   and all required libraries.

3. **Build `libsecp256k1` for Windows** (the vendored library must be
   compiled separately because it is not part of the depends system):
   ```bash
   cd external/libsecp256k1
   rm -rf build-win install-win        # clean any previous artifacts
   mkdir -p build-win && cd build-win
   cmake \
     -DCMAKE_TOOLCHAIN_FILE=../../../contrib/depends/x86_64-w64-mingw32/share/toolchain.cmake \
     -DCMAKE_INSTALL_PREFIX=../install-win \
     -DBUILD_SHARED_LIBS=OFF \
     -DSECP256K1_BUILD_BENCHMARK=OFF \
     -DSECP256K1_BUILD_TESTS=OFF \
     ..
   make -j$(nproc)
   make install
   cd ../../..
   ```

4. **Configure and build the main project** (from the repository root):
   ```bash
   mkdir -p build/x86_64-w64-mingw32/release
   cd build/x86_64-w64-mingw32/release
   cmake \
     -DCMAKE_TOOLCHAIN_FILE=../../../contrib/depends/x86_64-w64-mingw32/share/toolchain.cmake \
     -DSECP256K1_INCLUDE_DIR=../../../../external/libsecp256k1/include \
     -DSECP256K1_LIBRARY=../../../../external/libsecp256k1/install-win/lib/libsecp256k1.a \
     ../../..
   make -j$(nproc)
   ```

5. **Output binaries** are located in `build/x86_64-w64-mingw32/release/bin`:
   - `vnsd.exe`
   - `vns-wallet-cli.exe`
   - `vns-wallet-rpc.exe`

### Troubleshooting common build issues

- **Missing `libsecp256k1.a` during Windows cross‑compile:**  
  Run the `libsecp256k1` build steps from step 3 above. The CMake build
  system will also print explicit instructions if the file is not found.

- **Boost version mismatch:** Ensure you have Boost ≥ 1.66.

- **CMake can't find toolchain file:**  
  Verify that the `depends` build completed successfully. The toolchain is
  generated at `contrib/depends/x86_64-w64-mingw32/share/toolchain.cmake`.
  If it is missing, rerun step 2.

- **Out of memory during linking:** Increase swap space or reduce parallel
  jobs (e.g., `make -j2`).

- **OpenSSL issues:** Make sure the development package is installed.

- **ixwebsocket TLS errors on Windows:** If you get `400 Bad Request` when
  connecting to `wss://` relays, try using the `--nostr-allow-insecure` flag
  with `vnsd` (if implemented) or ensure your system's CA certificates are
  up to date.
## Using VNS

### Running the daemon (vnsd)

#### Current mainnet bootstrap policy

VeilRoot MAINNET is currently in **founder-bootstrap privacy mode by default**.

A normal zero-flag start requires a local Tor SOCKS proxy at:

```text
127.0.0.1:9050
```

If Tor is not running there, `vnsd` will exit with an error instead of falling back to clearnet.

Default start:

```bash
./vnsd
```

In the default founder mode, `vnsd` automatically:

- checks that local Tor is available at `127.0.0.1:9050`
- routes MAINNET P2P through Tor
- binds the public IPv4 listener to `127.0.0.1` instead of `0.0.0.0`
- forces `--hide-my-port`
- uses the active Tor bootstrap seeds

Current active Tor bootstrap seeds:

```text
nzc2tvcet4225q7mapuu6esxio2j4hvyv5zqsch7fitmqzejwqtccpad.onion:28084
4f66cwriyscavxemicrllyvklztonh5izdahqlbi4pbnhjnbzedcvdqd.onion:28084
```

This means the daemon requires **zero VeilRoot flags**, but Tor itself must be installed and running.

#### Linux quick start

Install and start Tor:

```bash
sudo apt update
sudo apt install tor
sudo systemctl enable --now tor
```

Verify Tor is listening:

```bash
ss -ltnp | grep 9050
```

Start VeilRoot:

```bash
./vnsd
```

If Tor is not running, `vnsd` will fail closed.

#### Windows quick start

1. Download the Tor Expert Bundle from:

```text
https://www.torproject.org/download/tor/
```

2. Extract it, for example, to:

```text
C:\tor-expert
```

3. Create the folders/files:

```text
C:\tor-expert\Data
C:\tor-expert\torrc
```

4. Put this into `C:\tor-expert\torrc`:

```text
SocksPort 9050
DataDirectory C:\tor-expert\Data
Log notice file C:\tor-expert\Data\notice.log
```

5. Start Tor in one PowerShell window:

```powershell
C:\tor-expert\tor\tor.exe -f C:\tor-expert\torrc
```

6. Keep that window open. Wait for:

```text
Bootstrapped 100% (done): Done
```

7. In another PowerShell window, verify Tor:

```powershell
Test-NetConnection -ComputerName 127.0.0.1 -Port 9050
```

It should show:

```text
TcpTestSucceeded : True
```

8. Start VeilRoot:

```powershell
cd C:\Users\<your-user>\temp
.\vnsd.exe
```

If you are using a different local Tor port, currently the default founder mode expects `9050`. Use the standard `9050` unless the code or installer is changed later.

#### Privacy modes

- `founder` / `founder_bootstrap` — default

  Tor is required. The daemon does not expose a direct public clearnet P2P listener and does not advertise the user's IP.

  ```bash
  ./vnsd
  ```

  Or explicitly:

  ```bash
  ./vnsd --network-privacy-mode=founder
  ```

- `mixed` / `public_mixed` — reserved for Phase 2

  This restores normal Monero-style public IPv4/IPv6 P2P behavior and does not require Tor.

  ```bash
  ./vnsd --network-privacy-mode=mixed
  ```

  **Important:** the VeilRoot public clearnet bootstrap list is currently empty. In mixed mode, a daemon will not find public peers automatically until independent public IPv4/IPv6 seed nodes or VeilRoot DNS seed hosts are added.

  For now, mixed mode is only useful with manual peer flags:

  ```bash
  ./vnsd --network-privacy-mode=mixed --seed-node <public-ip>:28080
  ```

  Do not use mixed mode as a novice default until public seed infrastructure exists.

See `./vnsd --help` for all options.

### Wallet commands

The wallet CLI (`vns-wallet-cli`) supports the following VNS-specific commands.  
**Note:** All commands accept the `--help` option for detailed usage.

| Command | Description |
|---------|-------------|
| `register_domain <domain> --relay=<relay_url>` | Register a new domain (burns the registration fee). You will be prompted for your Nostr private key. |
| `transfer_domain <domain> <new_owner_address>` | Transfer ownership to a new Nostr public key (33‑byte hex). |
| `update_domain_metadata <domain> [--new-owner=...] [--new-relay=...]` | Update the owner and/or relay URL. |
| `domain_info <domain>` | Display the on‑chain domain record (status, fee, fingerprint, etc.). |
| `domain_fee <extension>` | Show the registration fee for a given extension. |
| `domain_extensions` | List all currently supported extensions (e.g., `free`, `art`, `net`). |
| `submit_heartbeat <domain> --txid=<txid> [--private-key=...]` | Submit a heartbeat (kind 30001) to the relay. The `txid` must be the registration transaction ID. |
| `publish_service_descriptor <domain> <content_json> [--private-key=...]` | Publish a service descriptor (kind 30003) to the relay. The content can be a simple URL or a JSON object. |
| `resolve_domain <domain>` | Resolve a domain to its current service descriptor (retrieved from the relay and verified). |
| `get_domain_proof <txid>` | Retrieve the Merkle proof for a registration transaction (used internally). |

#### Important syntax notes

- The domain must always include the double dot, e.g. `myblog..net`.
- For `publish_service_descriptor`, the `<content_json>` argument can be:
  - A plain URL string (no quotes needed on Windows Command Prompt, e.g. `http://192.168.1.5:8080`)
  - A JSON object. On Linux/macOS (bash) use single quotes:  
    `publish_service_descriptor myblog..net '{"url":"http://192.168.1.5:8080","description":"My blog"}'`  
    On Windows Command Prompt, you must escape double quotes, or use a compact JSON without spaces and enclose the whole thing in double quotes:  
    `publish_service_descriptor myblog..net "{\"url\":\"http://192.168.1.5:8080\",\"description\":\"My blog\"}"`
- The `--private-key` flag is optional; if omitted, the wallet will use the key associated with the registrant (if stored) or prompt you interactively.

### Resolution API

The daemon exposes an RPC method `resolve_domain` that fetches and verifies the service descriptor from the relay. The wallet command `resolve_domain` is the primary interface. For programmatic use, you can call the JSON‑RPC endpoint directly:

```
POST /json_rpc
{
  "jsonrpc": "2.0",
  "id": "1",
  "method": "resolve_domain",
  "params": { "domain_name": "myblog..net" }
}
```

The response contains the `service_descriptor` field (as a string) and the domain metadata.

### End‑to‑end test

A typical workflow to register, publish, and resolve a domain:

1. **Start the daemon** and ensure it is fully synced.
2. **Open the wallet** and connect to the daemon.
3. **Register a domain:**
   ```
   register_domain myblog..net --relay=wss://relay.damus.io
   ```
   You will be prompted for your Nostr private key. After the transaction is mined (wait a few blocks), check the record:
   ```
   domain_info myblog..net
   ```
4. **Start a web server** (for testing, run a simple Python HTTP server on your local network).
5. **Publish the service descriptor:**  
   (Replace the IP with your server's address.)
   - On Linux/macOS:
     ```
     publish_service_descriptor myblog..net '{"url":"http://192.168.1.5:8080","description":"My blog"}'
     ```
   - On Windows Command Prompt:
     ```
     publish_service_descriptor myblog..net "{\"url\":\"http://192.168.1.5:8080\",\"description\":\"My blog\"}"
     ```
   Enter your private key when prompted.
6. **Submit a heartbeat** (use the registration txid shown after `register_domain`):
   ```
   submit_heartbeat myblog..net --txid=<txid>
   ```
7. **Resolve** the domain:
   ```
   resolve_domain myblog..net
   ```
   The output should display the service descriptor (the URL). You can now open that URL in a browser.

### Manual resolver (HTML page)

For quick testing without a browser extension, you can use the following self‑contained HTML page. Save it as `resolve.html` and open it in your browser (works on any OS). It calls the daemon's RPC and shows the resolved URL.

```html
<!DOCTYPE html>
<html>
<head>
  <title>VNS Resolver</title>
</head>
<body>
  <h1>VNS Resolver (manual)</h1>
  <p>Enter a double‑dotted domain (e.g., myblog..net):</p>
  <input type="text" id="domain" placeholder="myblog..net" size="30">
  <button onclick="resolve()">Resolve</button>
  <div id="result" style="margin-top:1em;font-size:1.2em;"></div>

  <script>
    async function resolve() {
      const domain = document.getElementById('domain').value.trim();
      if (!domain) return;
      const resultDiv = document.getElementById('result');
      resultDiv.textContent = 'Resolving...';
      try {
        const response = await fetch('http://localhost:28081/json_rpc', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: '1',
            method: 'resolve_domain',
            params: { domain_name: domain }
          })
        });
        const data = await response.json();
        if (data.result && data.result.service_descriptor) {
          let target = data.result.service_descriptor;
          // If it's a JSON string, try to extract 'url'
          try {
            const obj = JSON.parse(target);
            if (obj.url) target = obj.url;
          } catch(e) {}
          resultDiv.innerHTML = `<a href="${target}" target="_blank">${target}</a> (click to open)`;
        } else {
          resultDiv.textContent = 'Domain not found or not active.';
        }
      } catch(err) {
        resultDiv.textContent = 'Error: ' + err.message;
      }
    }
  </script>
</body>
</html>
```

Make sure your daemon is running on `http://localhost:28081` before using this page.

### Browser extension

Work is currently underway on a browser extension for resolving VeilRoot VNS double-dotted domains. It will be published when it is ready.

Anyone who develops a browser extension, or a dedicated browser such as a Tor-based browser, capable of resolving `[name]..[extension]` VNS namespaces is welcome to do so and is encouraged to make the project known to VeilRoot users.

Technically, such software should recognize VNS double-dotted names such as `myblog..net` as VNS namespaces rather than conventional DNS hostnames. It should resolve the name through the local VeilRoot daemon or another trusted VNS resolver, obtain and verify the corresponding on-chain domain record and Nostr service descriptor, verify the associated cryptographic fingerprint and Merkle proof, and then connect the user to the resolved service address (for example an onion service, HTTPS endpoint, or IPFS resource).

The resolver should perform these checks transparently so that users can enter a VNS name directly in the browser address bar and have it resolved without requiring manual conversion to an underlying service address.
## Internationalization

See [README.i18n.md](docs/README.i18n.md).

## Using Tor

For the current MAINNET Phase 1 network, Tor is built into the default founder-bootstrap mode. You do **not** need `torsocks`, and you do **not** need to manually pass `--tx-proxy` or `--proxy`.

The default mode uses:

```text
network-privacy-mode=founder
Tor SOCKS: 127.0.0.1:9050
```

Tor must be installed and running before `vnsd` starts.

If you are running a Tor onion-service seed node, configure a hidden service in Tor and pass `--anonymous-inbound`.

Example Linux Tor seed configuration:

```text
HiddenServiceDir /var/lib/tor/veilroot/
HiddenServicePort 28084 127.0.0.1:28084
```

Then start VeilRoot with:

```bash
./vnsd --anonymous-inbound <your-onion>.onion:28084,127.0.0.1:28084
```

Do not set `HiddenServicePort` to a port already used by P2P, RPC, or ZMQ. The current Tor P2P internal port is:

```text
28084
```

When VeilRoot later transitions to the mature mixed-network phase, Tor will become optional and can be enabled explicitly with:

```bash
./vnsd --network-privacy-mode=founder
```

## Pruning

Pruning is inherited from Monero and is available in VeilRoot.

The daemon supports Monero-style blockchain pruning, which reduces disk usage while still allowing normal validation and synchronization.

For current pruning-related flags, run:

```bash
./vnsd --help
```

The main Monero-derived pruning flag is:

```bash
./vnsd --prune-blockchain
```

Do not enable pruning on an important public seed node unless you understand that a pruned node has a reduced ability to serve historical block data to other peers.

## Debugging

Refer to Monero's debugging guide; the tools (`gdb`, `valgrind`, `ASAN`) work identically.

## Known issues

- **Windows TLS for WebSocket:** Some relays may reject connections from Windows due to CA certificate issues. Use the `--nostr-allow-insecure` flag (if implemented) or set the `SSL_CERT_FILE` environment variable to a valid CA bundle.
- **Blockchain sync:** Initial sync may take several hours; consider using a fast pruned node if available.
- **Merkle proof generation:** The wallet may log `Failed to parse block from blob` when building proofs – this is harmless and falls back to RPC data.
- **Event parsing fix:** As of v0.18.5.0, the Nostr event parsers have been corrected to handle the standard `["EVENT", <subscription_id>, <event_object>]` format. If you experience timeouts, ensure you are using the latest build.

---

*This README is adapted from the Monero project and updated for VeilRoot Name System. For the latest changes, see the commit history.*