# Network Graph Visualizer — Supporting Files

Files used by `auxiliary/analyze/network_graph`.

## Directory contents

| File | Purpose |
|------|---------|
| `network_map_template.html` | D3.js graph template — populated and saved as loot by the module |
| `d3.v7.9.0.min.js` | Local D3.js v7.9.0 — used when `EMBED_JS true` is set |
| `seed_data.rb` | Test data script — populates a workspace with a realistic 3-layer network |
| `README.md` | This file |

---

## Populating test data with seed_data.rb

`seed_data.rb` creates a realistic 3-layer network in the active workspace:

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
- 10 vulnerabilities (EternalBlue, Log4Shell, BlueKeep, etc.)
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