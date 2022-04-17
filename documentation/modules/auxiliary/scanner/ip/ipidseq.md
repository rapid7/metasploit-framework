## Vulnerable Application

This `auxiliary/scanner/ip/ipidseq` module will probe hosts' IPID sequences and classify them
using the same method Nmap uses when it's performing its IPID Idle Scan (-sI) and OS Detection (-O).

The module should only be used in internal networks.  Additionally, administrative/root permissions
are required to successfully capture on the device/interface.

Possible methods of IPID generation:

1. Unknown
2. Randomized
3. All zeros
4. Random positive increments
5. Constant
6. Broken little-endian incremental
7. Incremental

### Nmap Idle Scan

Nmap's probes are SYN/ACKs while this module's are SYNs.
While this does not change the underlying functionality,
it does change the chance of whether or not the probe will be stopped by a firewall.

Nmap's Idle Scan can use hosts whose IPID sequences are classified as "Incremental" or "Broken little-endian incremental".

More information: https://nmap.org/book/idlescan.html

## Verification Steps

1. Start msfconsole
1. Do: `use auxiliary/scanner/ip/ipidseq`
1. Do: `set RHOSTS [ip]`
1. Do: `run`

## Options

### SNAPLEN
The number of bytes to capture. Defaults to `65535`.

### GATEWAY_PROBE_HOST
Send a TTL=1 random UDP datagram to this host to discover the default gateway's MAC. Defaults to `8.8.8.8`.

### SAMPLES
The IPID sample size. Must be greater than `2`. Defaults to `6`.

### SECRET
A 32-bit cookie for probe requests. Defaults to `1297303073`.

## Scenarios

### Example Incremental

```
msf6 auxiliary(scanner/ip/ipidseq) > set RHOSTS 10.0.20.254
RHOSTS => 10.0.20.254
msf6 auxiliary(scanner/ip/ipidseq) > exploit

[*] 10.0.20.254's IPID sequence class: Incremental!
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
