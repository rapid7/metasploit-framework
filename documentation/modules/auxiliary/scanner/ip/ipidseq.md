## Vulnerable Application

This ```auxiliary/scanner/ip/ipidseq``` module will probe hosts' IPID sequences and classify them using the same method Nmap uses when it's performing its IPID Idle Scan (-sI) and OS Detection (-O).

More information: https://nmap.org/book/idlescan.html

Nmap's probes are SYN/ACKs while this module's are SYNs.
While this does not change the underlying functionality, it does change the chance of whether or not the probe will be stopped by a firewall.

Nmap's Idle Scan can use hosts whose IPID sequences are classified as "Incremental" or "Broken little-endian incremental".

## Verification Steps

1. Start msfconsole
1. Do: `use auxiliary/scanner/ip/ipidseq`
1. Do: `set RHOSTS [ip]`
1. Do: `run` or `exploit`

## Options

```
Basic options:
  Name       Current Setting  Required  Description
  ----       ---------------  --------  -----------
  INTERFACE                   no        The name of the interface
  RHOSTS     10.0.20.254      yes       The target host(s)
  RPORT      80               yes       The target port
  SNAPLEN    65535            yes       The number of bytes to capture
  THREADS    1                yes       The number of concurrent threads (max one per host)
  TIMEOUT    500              yes       The reply read timeout in milliseconds
```

### Advanced Options
```
   Name                 Current Setting  Required  Description
   ----                 ---------------  --------  -----------
   GATEWAY_PROBE_HOST   8.8.8.8          yes       Send a TTL=1 random UDP datagram to this host to discover the default gateway's MAC
   GATEWAY_PROBE_PORT                    no        The port on GATEWAY_PROBE_HOST to send a random UDP probe to (random if 0 or unset)
   SAMPLES              6                yes       The IPID sample size
   SECRET               1297303073       yes       A 32-bit cookie for probe requests.
   ShowProgress         true             yes       Display progress messages during a scan
   ShowProgressPercent  10               yes       The interval in percent that progress should be shown
   VERBOSE              false            no        Enable detailed status messages
   WORKSPACE                             no        Specify the workspace for this module

```

Required Options:
1. RHOSTS


## Scenarios
Possible output:
1. Unknown
2. Randomized
3. All zeros
4. Random positive increments
5. Constant
6. Broken little-endian incremental!
7. Incremental!


### Example Incremental

```
msf6 auxiliary(scanner/ip/ipidseq) > set RHOSTS 10.0.20.254
RHOSTS => 10.0.20.254
msf6 auxiliary(scanner/ip/ipidseq) > exploit

[*] 10.0.20.254's IPID sequence class: Incremental!
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Example Host down 

```
msf6 auxiliary(scanner/ip/ipidseq) > run

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Example Range scanning

```
msf6 auxiliary(scanner/ip/ipidseq) > set RHOSTS 10.0.20.0-10.0.20.254
RHOSTS => 10.0.20.0-10.0.20.254
msf6 auxiliary(scanner/ip/ipidseq) > run

[*] Scanned  26 of 255 hosts (10% complete)
[*] 10.0.20.30's IPID sequence class: Incremental!
[*] Scanned  51 of 255 hosts (20% complete)
```