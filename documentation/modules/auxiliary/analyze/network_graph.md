## Vulnerable Application

Generates an interactive network graph visualization from hosts, sessions,
and routes stored in the Metasploit database. The output is a self-contained
HTML file saved via store_loot that can be opened in any modern web browser.
Features include draggable nodes, device-type icons with click-to-override,
OS-specific icons, compromise indicators, path highlighting back to the MSF
node, and a details panel showing host information.

### Example data

The `data/auxiliary/analyze/network_map` folder includes a `README.md` and `seed_data.rb`.
The readme file has instructions, which are duplicated here, on how to import the seed data
to make an interesting graph for testing purposes.

To import the example data:

```
workspace -a network_graph_test
irb
load 'data/auxiliary/analyze/network_map/seed_data.rb'
exit
```

## Verification Steps

1. Start msfconsole
1. Have data in your database, or import the example data
1. Do: `use auxiliary/analyze/network_graph`
1. Do: `run`
1. Open the loot file in a browser

## Options

### EMBED_JS

Embed D3.js inline for a fully self-contained offline HTML file. Defaults to `false`

### LIMIT_SESSION

Max sessions to include per host (0 = unlimited, most recent first). Defaults to `0`

### LIMIT_LOOT

Max loot items to include per host (0 = unlimited, most recent first). Defaults to `0`

### LIMIT_CRED

Max credentials to include per host (0 = unlimited). Defaults to `0`

## Scenarios

### Version and OS

```
msf > workspace -a network_graph_test
[*] Added workspace: network_graph_test
[*] Workspace: network_graph_test
msf > irb
[*] Starting IRB shell...
[*] You are in the "framework" object

>> load 'data/auxiliary/analyze/network_map/seed_data.rb'
[*] Workspace: network_graph_test
[+] Host 192.168.1.10 — DESKTOP-CORP01
[+] Host 192.168.1.20 — web01.corp.local
[+] Host 192.168.1.50 — core-sw01
[+] Host 10.10.0.10 — db01.internal
[+] Host 10.10.0.20 — SRV-FILES01
[+] Host 10.10.0.30 — mail01.internal
[+] Host 10.10.0.100 — hp-lj-m501dn
[+] Host 172.16.5.10 — DC01.corp.local
[+] Host 172.16.5.20 — pgdb01.corp.local
[+] Host 172.16.5.30 — esxi01.corp.local
[+] Services 192.168.1.10
[+] Services 192.168.1.20
[+] Services 192.168.1.50
[+] Services 10.10.0.10
[+] Services 10.10.0.20
[+] Services 10.10.0.30
[+] Services 10.10.0.100
[+] Services 172.16.5.10
[+] Services 172.16.5.20
[+] Services 172.16.5.30
[+] Session 192.168.1.10 — ms17_010_eternalblue
[+] Session 192.168.1.20 — struts2_rest_xstream
[+] Session 10.10.0.10 — apache_log4j_rce
[+] Session 10.10.0.20 — ms17_010_psexec
[+] Session 172.16.5.10 — psexec
[+] Session 172.16.5.10 — ms14_068_kerberos_checksum
[+] Cred Administrator@192.168.1.10:445 (ntlm_hash, Successful)
[+] Cred Administrator@10.10.0.20:445 (ntlm_hash, Untried)
[+] Cred Administrator@172.16.5.10:445 (ntlm_hash, Successful)
[+] Cred krbtgt@172.16.5.10:445 (ntlm_hash, Successful)
[+] Cred jsmith@192.168.1.10:3389 (password, Successful)
[+] Cred jsmith@10.10.0.20:3389 (password, Untried)
[+] Cred svc-backup@172.16.5.10:389 (password, Successful)
[+] Cred svc-backup@10.10.0.20:445 (password, Untried)
[+] Cred svc-sql@10.10.0.20:1433 (password, Untried)
[+] Cred svc-sql@172.16.5.10:445 (password, Untried)
[+] Cred root@192.168.1.20:22 (password, Successful)
[+] Cred root@10.10.0.10:22 (password, Successful)
[+] Cred root@172.16.5.20:22 (password, Untried)
[+] Cred root@10.10.0.30:22 (password, Untried)
[+] Cred webapp@192.168.1.20:3306 (password, Successful)
[+] Cred webapp@10.10.0.10:3306 (password, Untried)
[+] Cred deployer@192.168.1.20:22 (password, Successful)
[+] Cred deployer@172.16.5.20:22 (password, Untried)
[+] Cred dbadmin@10.10.0.10:5432 (password, Successful)
[+] Cred dbadmin@172.16.5.20:5432 (password, Untried)
[+] Cred postgres@10.10.0.10:5432 (password, Untried)
[+] Cred postgres@172.16.5.20:5432 (password, Untried)
[+] Cred root@192.168.1.20:22 (password, Successful)
[+] Cred deployer@172.16.5.20:22 (password, Untried)
[+] Cred admin@192.168.1.50:22 (password, Successful)
[+] Cred cisco@192.168.1.50:23 (password, Untried)
[+] Cred root@172.16.5.30:22 (password, Untried)
[+] Cred krbtgt@172.16.5.10:88 (krb_enc_key, Successful)
[+] Traceroute 192.168.1.10 (1 hop)
[+] Traceroute 192.168.1.20 (1 hop)
[+] Traceroute 192.168.1.50 (1 hop)
[+] Traceroute 10.10.0.10 (3 hops)
[+] Traceroute 10.10.0.20 (3 hops)
[+] Traceroute 10.10.0.30 (3 hops)
[+] Traceroute 10.10.0.100 (3 hops)
[+] Traceroute 172.16.5.10 (5 hops)
[+] Traceroute 172.16.5.20 (5 hops)
[+] Traceroute 172.16.5.30 (5 hops)
[+] Vuln 192.168.1.10:445 — MS17-010 EternalBlue
[+] Vuln 192.168.1.10:3389 — BlueKeep
[+] Vuln 192.168.1.20:80 — Apache Struts2 RCE
[+] Vuln 192.168.1.20:3306 — MySQL Weak Credentials
[+] Vuln 10.10.0.10:80 — Log4Shell
[+] Vuln 10.10.0.10:5432 — PostgreSQL Weak Credentials
[+] Vuln 10.10.0.20:445 — MS17-010 EternalBlue
[+] Vuln 10.10.0.20:1433 — MSSQL Weak SA Credentials
[+] Vuln 172.16.5.10:88 — MS14-068 Kerberos PAC Forgery
[+] Vuln 172.16.5.30:443 — VMware vCenter RCE
[+] Loot 192.168.1.10 — SAM Hashes
[+] Loot 192.168.1.10 — LSA Secrets
[+] Loot 192.168.1.10 — Chrome History
[+] Loot 192.168.1.10 — Whoami Output
[+] Loot 192.168.1.20 — /etc/passwd
[+] Loot 192.168.1.20 — /etc/shadow
[+] Loot 192.168.1.20 — authorized_keys
[+] Loot 192.168.1.20 — nginx.conf
[+] Loot 192.168.1.20 — db.config.php
[+] Loot 10.10.0.10 — /etc/passwd
[+] Loot 10.10.0.10 — /etc/shadow
[+] Loot 10.10.0.10 — id_rsa (root)
[+] Loot 10.10.0.10 — mysql_dump.sql
[+] Loot 10.10.0.10 — crontab -l (root)
[+] Loot 10.10.0.10 — /proc/1/environ
[+] Loot 172.16.5.10 — NTDS.dit Hashes
[+] Loot 172.16.5.10 — LDAP Dump
[+] Loot 172.16.5.10 — Golden Ticket
[+] Loot 172.16.5.10 — GPO Dump
[+] Loot 172.16.5.10 — SAM Hive
[+] Loot 172.16.5.10 — SYSTEM Hive
[+] Loot 172.16.5.10 — Mimikatz Output
[+] Loot 172.16.5.10 — Security Event Log
[+] ModuleRun 192.168.1.10 — smb_version
[+] ModuleRun 192.168.1.10 — smb_ms17_010
[+] ModuleRun 192.168.1.10 — http_version
[+] ModuleRun 192.168.1.20 — ssh_version
[+] ModuleRun 192.168.1.20 — http_version
[+] ModuleRun 192.168.1.20 — ssl_version
[+] ModuleRun 192.168.1.50 — ssh_version
[+] ModuleRun 192.168.1.50 — snmp_enum
[+] ModuleRun 192.168.1.50 — http_version
[+] ModuleRun 10.10.0.10 — ssh_version
[+] ModuleRun 10.10.0.10 — ssl_version
[+] ModuleRun 10.10.0.10 — mysql_version
[+] ModuleRun 10.10.0.10 — postgres_version
[+] ModuleRun 10.10.0.20 — smb_version
[+] ModuleRun 10.10.0.20 — smb_ms17_010
[+] ModuleRun 10.10.0.20 — ssl_version
[+] ModuleRun 10.10.0.20 — mssql_ping
[+] ModuleRun 10.10.0.30 — ssh_version
[+] ModuleRun 10.10.0.30 — smtp_version
[+] ModuleRun 10.10.0.30 — ssl_version
[+] ModuleRun 10.10.0.100 — http_version
[+] ModuleRun 10.10.0.100 — snmp_enum
[+] ModuleRun 172.16.5.10 — smb_version
[+] ModuleRun 172.16.5.10 — ssl_version
[+] ModuleRun 172.16.5.20 — ssh_version
[+] ModuleRun 172.16.5.20 — postgres_version
[+] ModuleRun 172.16.5.20 — mysql_version
[+] ModuleRun 172.16.5.30 — ssh_version
[+] ModuleRun 172.16.5.30 — http_version
[+] ModuleRun 172.16.5.30 — ssl_version

[*] Done. Verify with: hosts / services / creds / vulns / loot
[*] Generate graph:   use auxiliary/analyze/network_graph && run
=> true
>> exit
msf > use auxiliary/analyze/network_graph
[*] Using configured payload windows/meterpreter/reverse_tcp
msf auxiliary(analyze/network_graph) > run
[*] Building network graph:
[*]   Hosts:             10
[*]   Sessions:          6
[*]   Traceroutes:       10
[*]   Loot items:        23
[*]   Vulns:             10
[*]   Module events:     1
[*]   Module runs:       30
[*]   Credential logins: 28
[+] Network graph saved to: /root/.msf4/loot/20260521201023_network_graph_te_unknown_network.graph_303089.html
[*] Auxiliary module execution completed
msf auxiliary(analyze/network_graph) > 
```
