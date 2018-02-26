## Vulnerable Application

  Any system exposing the remote desktop protocol, RDP, typically on 3389/TCP.

## Verification Steps

  1. Do: ```use auxiliary/scanner/rdp/rdp_scanner```
  2. Do: ```set [RHOSTS]```, replacing ```[RHOSTS]``` with a list of hosts to test for the presence of RDP
  3. Do: ```run```
  4. If the host is exposing an identifiable RDP instance, it will print the endpoint.

## Options

  There are three options currently supported that control what security protocols to
  send in the RDP negotiation request, which can be helpful in identifying RDP
  endpoints that might be locked down or configured differently:

  **TLS** Set to true to request TLS security support
  **CredSSP** Set to true to request CredSSP support
  **EarlyUser** Set to true to request Early User Authorization Result PDU support

## Scenarios

  ```
msf auxiliary(rdp_scanner) > run

[+] 10.4.18.26:3389       - Identified RDP
[+] 10.4.18.22:3389       - Identified RDP
[+] 10.4.18.89:3389       - Identified RDP
[+] 10.4.18.9:3389        - Identified RDP
[+] 10.4.18.67:3389       - Identified RDP
[+] 10.4.18.80:3389       - Identified RDP
[+] 10.4.18.34:3389       - Identified RDP
[+] 10.4.18.70:3389       - Identified RDP
[+] 10.4.18.30:3389       - Identified RDP
[+] 10.4.18.76:3389       - Identified RDP
[+] 10.4.18.13:3389       - Identified RDP
[+] 10.4.18.91:3389       - Identified RDP
[+] 10.4.18.5:3389        - Identified RDP
[+] 10.4.18.47:3389       - Identified RDP
[+] 10.4.18.41:3389       - Identified RDP
[+] 10.4.18.105:3389      - Identified RDP
[*] Scanned  44 of 256 hosts (17% complete)
[*] Scanned  55 of 256 hosts (21% complete)
[+] 10.4.18.118:3389      - Identified RDP
[+] 10.4.18.108:3389      - Identified RDP
[+] 10.4.18.139:3389      - Identified RDP
[*] Scanned  94 of 256 hosts (36% complete)
[*] Scanned 110 of 256 hosts (42% complete)
[+] 10.4.18.157:3389      - Identified RDP
[+] 10.4.18.166:3389      - Identified RDP
[+] 10.4.18.164:3389      - Identified RDP
[+] 10.4.18.170:3389      - Identified RDP
[+] 10.4.18.185:3389      - Identified RDP
[+] 10.4.18.209:3389      - Identified RDP
[+] 10.4.18.188:3389      - Identified RDP
[*] Scanned 156 of 256 hosts (60% complete)
[+] 10.4.18.237:3389      - Identified RDP
[+] 10.4.18.225:3389      - Identified RDP
[*] Scanned 186 of 256 hosts (72% complete)
[*] Scanned 194 of 256 hosts (75% complete)
[*] Scanned 208 of 256 hosts (81% complete)
[*] Scanned 253 of 256 hosts (98% complete)
[*] Scanned 256 of 256 hosts (100% complete)
[*] Auxiliary module execution completed
```
