# Network Graph Visualizer — Supporting Files

Files used by `auxiliary/analyze/network_graph`.

## Directory contents

| File | Purpose |
|------|---------|
| `network_map_template.html` | D3.js graph template — populated and saved as loot by the module |
| `d3.v7.9.0.min.js` | Local D3.js v7.9.0 — used when `EMBED_JS true` is set |
| `seed_data.rb` | Test data script — populates a workspace with a synthetic 3-layer network |
| `README.md` | This file |

---

## Vendored D3

`d3.v7.9.0.min.js` is the official D3 v7.9.0 browser bundle from
`https://cdn.jsdelivr.net/npm/d3@7.9.0/dist/d3.min.js`. To reproduce and verify
it without executing package lifecycle scripts:

```
curl -L --fail --output /tmp/d3.v7.9.0.min.js https://cdn.jsdelivr.net/npm/d3@7.9.0/dist/d3.min.js
echo 'f2094bbf6141b359722c4fe454eb6c4b0f0e42cc10cc7af921fc158fceb86539  /tmp/d3.v7.9.0.min.js' | sha256sum --check
cmp /tmp/d3.v7.9.0.min.js data/auxiliary/analyze/network_map/d3.v7.9.0.min.js
```

Offline reports fail with a configuration error when the bundle is missing
instead of silently running remote JavaScript. The explicit `EMBED_JS false`
mode pins this same artifact with its SHA-512 Subresource Integrity digest.

The source and build configuration are tagged at
`https://github.com/d3/d3/tree/v7.9.0`. To rebuild instead of downloading the
published bundle, clone that tag into a temporary directory and run:

```
corepack yarn install --frozen-lockfile --ignore-scripts
corepack yarn run prepublishOnly
sha256sum dist/d3.min.js
```

Run the commands only in the temporary upstream checkout: its build task removes
and recreates `dist`. D3's copyright and ISC terms are recorded in the
repository-root `LICENSE` and included in every generated report.

---

## Populating test data with seed_data.rb

`seed_data.rb` creates a synthetic 3-layer network in the active workspace.
All identities and secrets are deterministic Faker-generated test values and
are marked accordingly; none is suitable for use as a real credential.

```
              MSF (192.168.0.100)
                      |
              192.168.0.1  [gateway hop]
             /          |          \
     192.168.1.10  192.168.1.20  192.168.1.50
     Win10 (pwnd)  Ubuntu (pwnd)  Cisco IOS
                        |
                   10.10.0.1  [router hop]
              /      |       |        \
        10.10.0.10  .20     .30     .100
        Deb (pwnd) WinSrv  FreeBSD  Printer
             |
        172.16.5.1  [router hop]
         /      |        \
   172.16.5.10  .20      .30
   WinDC (pwnd) RHEL    VMware ESXi
```

**What gets created:**

- 10 hosts across three subnets, each with 5 services
- 5 active sessions and 1 closed session (DC was hit twice)
- 16 credentials — 5 CORP domain accounts shared across Windows boxes, 5 Linux accounts shared across Linux boxes, 2 SSH keys, 3 standalone accounts (Cisco, ESXi), 1 Kerberos AES-256 key (krbtgt Golden Ticket material)
- Traceroute notes driving the layered graph layout
- 13 SNMP notes describing routers, switches, ports, neighbors, and learned MAC addresses
- 18 vulnerabilities (EternalBlue, Log4Shell, BlueKeep, etc.)
- 23 loot items and 30 module-run records
- Router hop nodes at each subnet boundary (not counted in the 10 hosts)

### Steps

**1. Connect to a database**

```
msf6 > db_connect   # or db_status to verify an existing connection
```

**2. (Optional) Use a dedicated workspace**

```
msf6 > workspace -a network_graph_test
msf6 > workspace network_graph_test
```

**3. Load the seed script from irb**

```
msf6 > irb
>> load '/path/to/metasploit-framework/data/auxiliary/analyze/network_map/seed_data.rb'
>> exit
```

> **Note:** `load` runs in `main` binding, so the `framework` local variable from the IRB
> session is not in scope. The script resolves this via `ObjectSpace.each_object(Msf::Framework).first`.

**4. Verify the data**

```
msf6 > hosts
msf6 > services
msf6 > creds
msf6 > vulns
```

**5. Generate the graph**

```
msf6 > use auxiliary/analyze/network_graph
msf6 auxiliary(analyze/network_graph) > run
```

Open the reported `.html` path in a browser.

### Cleaning up

To remove the test data, delete the workspace:

```
msf6 > workspace -d network_graph_test
```

## Live viewer access

Run `load network_map`, then `network_map_start`, and open the printed URL. A
five-word HTTP Basic password is generated for the viewer and changes whenever
the server restarts. Rotating it with `network_map_password` disconnects
existing viewers. `network_map_status` prints the current URL but does not
redisplay the password; rotate it if the startup output is no longer available.
Console and module output is excluded from browser payloads by default because
it can contain credentials, tokens, hashes, or other data not present in the
graph. `--console-feed` opts in to sharing the short console tail; use it only
when every authenticated viewer is trusted with arbitrary console output.

The default listener is `127.0.0.1:4646`. Host headers and WebSocket origins
must match the viewer origin. For a shared listener, specify the exact origin
viewers will use, for example:

```
network_map_start 4646 --host 0.0.0.0 --origin http://192.0.2.10:4646
```

HTTP Basic does not encrypt the password or engagement data. For access over an
untrusted network, use HTTPS through a trusted reverse proxy, preserve the
viewer Host header, and set `--origin` to the HTTPS viewer origin. The embedded
server expires incomplete requests, caps request and WebSocket-frame sizes, and
accepts at most 64 simultaneous connections. Response writes have deadlines;
each viewer has a bounded update queue and is disconnected if it stops reading.
