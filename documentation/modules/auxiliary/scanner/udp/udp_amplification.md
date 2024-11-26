## Vulnerable Application

  Any reachable UDP endpoint is a potential target.

## Verification Steps

  Example steps in this format:

  1. Start `msfconsole`
  2. Do: ```use auxiliary/scanner/udp/udp_amplification```
  3. Do `set RHOSTS [targets]`, replacing ```[targets]``` with the hosts you wish to assess.
  4. Do ```set PORTS [ports]```, replacing ```[ports]``` with the list of UDP ports you wish to assess on each asset.
  5. Optionally, ```set PROBE [probe]```, replacing ```[probe]``` with a string or `file://` resource to serve as the UDP payload
  6. Do: ```run```
  7. If any of the endpoints were discovered to be vulnerable to UDP amplification with the probe you specified, status will be printed indicating as such.

## Options

  **PORTS**

  This is the list of ports to test for UDP amplification on each host.
  Formats like `1,2,3`, `1-3`, `1,2-3`, etc, are all supported.  You'll
  generally only want to specify a small, targeted set of ports with an
  appropriately tailored `PROBE` value, described below

  **PROBE**

  This is the payload to send in each UDP datagram. Unset or set to the empty
  string `''` or `""` to send empty UDP datagrams, or use the `file://`
  resource to specify a local file to serve as the UDP payload.

## Scenarios

  ```
  resource (amp.rc)> use auxiliary/scanner/udp/udp_amplification
  resource (amp.rc)> set RHOSTS 10.10.16.0/20 192.168.3.0/23
  RHOSTS => 10.10.16.0/20 192.168.3.0/23
  resource (amp.rc)> set PORTS 17,19,12345
  PORTS => 17,19,12345
  resource (amp.rc)> set THREADS 100
  THREADS => 100
  resource (amp.rc)> set PROBE 'test'
  PROBE => test
  resource (amp.rc)> run
  [*] Sending 4-byte probes to 3 port(s) on 10.10.16.0->10.10.16.255 (256 hosts)
  [*] Sending 4-byte probes to 3 port(s) on 10.10.18.0->10.10.18.255 (256 hosts)
  [*] Sending 4-byte probes to 3 port(s) on 10.10.20.0->10.10.20.255 (256 hosts)
  [*] Sending 4-byte probes to 3 port(s) on 10.10.21.0->10.10.21.255 (256 hosts)
  [*] Sending 4-byte probes to 3 port(s) on 10.10.22.0->10.10.22.255 (256 hosts)
  [*] Sending 4-byte probes to 3 port(s) on 10.10.23.0->10.10.23.255 (256 hosts)
  [*] Sending 4-byte probes to 3 port(s) on 10.10.24.0->10.10.24.255 (256 hosts)
  [*] Sending 4-byte probes to 3 port(s) on 10.10.25.0->10.10.25.255 (256 hosts)
  [*] Sending 4-byte probes to 3 port(s) on 10.10.27.0->10.10.27.255 (256 hosts)
  [*] Sending 4-byte probes to 3 port(s) on 10.10.28.0->10.10.28.255 (256 hosts)
  [*] Sending 4-byte probes to 3 port(s) on 10.10.29.0->10.10.29.255 (256 hosts)
  [*] Sending 4-byte probes to 3 port(s) on 10.10.30.0->10.10.30.255 (256 hosts)
  [*] Sending 4-byte probes to 3 port(s) on 10.10.31.0->10.10.31.255 (256 hosts)
  [*] Sending 4-byte probes to 3 port(s) on 192.168.3.0->192.168.3.255 (256 hosts)
  [*] Sending 4-byte probes to 3 port(s) on 192.168.4.0->192.168.4.255 (256 hosts)
  [*] Sending 4-byte probes to 3 port(s) on 10.10.17.0->10.10.17.255 (256 hosts)
  [*] Sending 4-byte probes to 3 port(s) on 10.10.19.0->10.10.19.255 (256 hosts)
  [*] Sending 4-byte probes to 3 port(s) on 10.10.26.0->10.10.26.255 (256 hosts)
  [*] Scanned  512 of 4608 hosts (11% complete)
  [+] 10.10.17.153:19 - susceptible to UDP amplification: No packet amplification and a 18x, 70-byte bandwidth amplification
  [+] 10.10.20.47:17 - susceptible to UDP amplification: No packet amplification and a 40x, 159-byte bandwidth amplification
  [*] Scanned 2560 of 4608 hosts (55% complete)
  [+] 10.10.23.199:19 - susceptible to UDP amplification: No packet amplification and a 256x, 1020-byte bandwidth amplification
  [+] 10.10.23.248:17 - susceptible to UDP amplification: No packet amplification and a 26x, 103-byte bandwidth amplification
  [*] Scanned 3584 of 4608 hosts (77% complete)
  [*] Scanned 3840 of 4608 hosts (83% complete)
  [+] 10.10.30.202:19 - susceptible to UDP amplification: No packet amplification and a 18x, 70-byte bandwidth amplification
  [*] Scanned 4096 of 4608 hosts (88% complete)
  [+] 192.168.3.64:19 - susceptible to UDP amplification: No packet amplification and a 18x, 70-byte bandwidth amplification
  [+] 192.168.3.71:19 - susceptible to UDP amplification: No packet amplification and a 18x, 70-byte bandwidth amplification
  [+] 192.168.3.73:19 - susceptible to UDP amplification: No packet amplification and a 18x, 70-byte bandwidth amplification
  [+] 192.168.3.77:19 - susceptible to UDP amplification: No packet amplification and a 18x, 70-byte bandwidth amplification
  [+] 192.168.3.100:19 - susceptible to UDP amplification: No packet amplification and a 18x, 70-byte bandwidth amplification
  [+] 192.168.3.113:19 - susceptible to UDP amplification: No packet amplification and a 18x, 70-byte bandwidth amplification
  [+] 192.168.3.118:19 - susceptible to UDP amplification: No packet amplification and a 18x, 70-byte bandwidth amplification
  [+] 192.168.4.253:19 - susceptible to UDP amplification: 2x packet amplification and a 37x, 144-byte bandwidth amplification
  [+] 192.168.3.178:19 - susceptible to UDP amplification: No packet amplification and a 18x, 70-byte bandwidth amplification
  [*] Scanned 4352 of 4608 hosts (94% complete)
  [+] 192.168.4.254:19 - susceptible to UDP amplification: 2x packet amplification and a 37x, 144-byte bandwidth amplification
  [*] Scanned 4608 of 4608 hosts (100% complete)
  [*] Auxiliary module execution completed
  ```

  Similarly, but with empty UDP datagrams instead:

  ```
  resource (amp.rc)> unset PROBE
  Unsetting PROBE...
  resource (amp.rc)> run
  [*] Sending 0-byte probes to 3 port(s) on 10.10.16.0->10.10.16.255 (256 hosts)
  [*] Sending 0-byte probes to 3 port(s) on 10.10.17.0->10.10.17.255 (256 hosts)
  [*] Sending 0-byte probes to 3 port(s) on 10.10.18.0->10.10.18.255 (256 hosts)
  [*] Sending 0-byte probes to 3 port(s) on 10.10.19.0->10.10.19.255 (256 hosts)
  [*] Sending 0-byte probes to 3 port(s) on 10.10.20.0->10.10.20.255 (256 hosts)
  [*] Sending 0-byte probes to 3 port(s) on 10.10.21.0->10.10.21.255 (256 hosts)
  [*] Sending 0-byte probes to 3 port(s) on 10.10.22.0->10.10.22.255 (256 hosts)
  [*] Sending 0-byte probes to 3 port(s) on 10.10.23.0->10.10.23.255 (256 hosts)
  [*] Sending 0-byte probes to 3 port(s) on 10.10.24.0->10.10.24.255 (256 hosts)
  [*] Sending 0-byte probes to 3 port(s) on 10.10.25.0->10.10.25.255 (256 hosts)
  [*] Sending 0-byte probes to 3 port(s) on 10.10.26.0->10.10.26.255 (256 hosts)
  [*] Sending 0-byte probes to 3 port(s) on 10.10.27.0->10.10.27.255 (256 hosts)
  [*] Sending 0-byte probes to 3 port(s) on 10.10.28.0->10.10.28.255 (256 hosts)
  [*] Sending 0-byte probes to 3 port(s) on 10.10.29.0->10.10.29.255 (256 hosts)
  [*] Sending 0-byte probes to 3 port(s) on 10.10.30.0->10.10.30.255 (256 hosts)
  [*] Sending 0-byte probes to 3 port(s) on 10.10.31.0->10.10.31.255 (256 hosts)
  [*] Sending 0-byte probes to 3 port(s) on 192.168.3.0->192.168.3.255 (256 hosts)
  [*] Sending 0-byte probes to 3 port(s) on 192.168.4.0->192.168.4.255 (256 hosts)
  [+] 10.10.17.229:17 - susceptible to UDP amplification: No packet amplification and a 107x, 107-byte bandwidth amplification
  [+] 10.10.26.252:19 - susceptible to UDP amplification: No packet amplification and a 3892x, 3892-byte bandwidth amplification
  [*] Scanned 4096 of 4608 hosts (88% complete)
  [+] 192.168.3.113:19 - susceptible to UDP amplification: No packet amplification and a 74x, 74-byte bandwidth amplification
  [+] 192.168.3.114:19 - susceptible to UDP amplification: No packet amplification and a 74x, 74-byte bandwidth amplification
  [+] 192.168.3.115:19 - susceptible to UDP amplification: No packet amplification and a 74x, 74-byte bandwidth amplification
  [+] 192.168.3.178:19 - susceptible to UDP amplification: No packet amplification and a 74x, 74-byte bandwidth amplification
  [+] 192.168.3.184:19 - susceptible to UDP amplification: No packet amplification and a 74x, 74-byte bandwidth amplification
  [*] Scanned 4352 of 4608 hosts (94% complete)
  [+] 192.168.4.253:19 - susceptible to UDP amplification: 2x packet amplification and a 148x, 148-byte bandwidth amplification
  [+] 192.168.4.254:19 - susceptible to UDP amplification: 2x packet amplification and a 148x, 148-byte bandwidth amplification
  [*] Scanned 4608 of 4608 hosts (100% complete)
  [*] Auxiliary module execution completed
  ```
