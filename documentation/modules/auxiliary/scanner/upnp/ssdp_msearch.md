## Vulnerable Application

This module discovers information from UPnP-enabled systems using SSDP (Simple Service Discovery Protocol) M-SEARCH requests. UPnP devices respond to these multicast discovery requests with information about their services, which can reveal device type, manufacturer, model, and potentially vulnerable software versions.

The module also identifies several known vulnerabilities in UPnP implementations:
- CVE-2012-5958: Portable SDK for UPnP Devices unique_service_name() Remote Code Execution
- CVE-2012-5959: Portable SDK for UPnP Devices unique_service_name() Remote Code Execution
- CVE-2013-0229: MiniUPnPd ProcessSSDPRequest() Out of Bounds Memory Access DoS
- CVE-2013-0230: MiniUPnPd ExecuteSoapAction memcpy() Remote Code Execution

### Installation

Many devices respond to SSDP, including routers, smart TVs, printers, and IoT devices. For testing purposes, you can set up a mock UPnP responder:

```bash
# Create a simple SSDP responder
mkdir -p ssdp_test
cd ssdp_test

cat > ssdp_responder.py << 'EOF'
import socket
import struct

MCAST_GRP = '239.255.255.250'
MCAST_PORT = 1900

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('', MCAST_PORT))

mreq = struct.pack("4sl", socket.inet_aton(MCAST_GRP), socket.INADDR_ANY)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

print(f"SSDP responder listening on {MCAST_GRP}:{MCAST_PORT}")

while True:
    data, addr = sock.recvfrom(1024)
    if b"M-SEARCH" in data:
        print(f"Received M-SEARCH from {addr}")
        
        response = b"""HTTP/1.1 200 OK\r
CACHE-CONTROL: max-age=1800\r
EXT:\r
LOCATION: http://192.0.2.10:80/description.xml\r
SERVER: Linux/3.10 UPnP/1.0 MiniUPnPd/1.0\r
ST: upnp:rootdevice\r
USN: uuid:12345678-1234-1234-1234-123456789012::upnp:rootdevice\r
\r
"""
        sock.sendto(response, addr)
        print(f"Sent response to {addr}")
EOF

# Run the responder
sudo python3 ssdp_responder.py
```

For a vulnerable MiniUPnPd version:

```bash
# Build MiniUPnPd 1.0 (vulnerable to CVE-2013-0229 and CVE-2013-0230)
git clone https://github.com/miniupnp/miniupnp.git
cd miniupnp/miniupnpd
git checkout miniupnpd_1_0

# Compile
sudo apt-get install -y iptables-dev
make

# Run (requires root)
sudo ./miniupnpd -f miniupnpd.conf
```

Using Docker for a vulnerable UPnP device simulator:

```bash
cat > Dockerfile << 'EOF'
FROM ubuntu:18.04
RUN apt-get update && \
    apt-get install -y python3 python3-pip && \
    rm -rf /var/lib/apt/lists/*

COPY ssdp_responder.py /app/
WORKDIR /app
EXPOSE 1900/udp
CMD ["python3", "ssdp_responder.py"]
EOF

docker build -t ssdp-responder .
docker run -d --network host --name ssdp ssdp-responder
```

## Verification Steps

1. Ensure you have UPnP-enabled devices on your network or set up the test environment as described above
2. Start msfconsole
3. Do: `use auxiliary/scanner/upnp/ssdp_msearch`
4. Do: `set RHOSTS [IP or IP range]`
5. Do: `run`
6. You should see discovered UPnP endpoints and any identified vulnerabilities

## Options

**RHOSTS**

The target address range or CIDR identifier

**RPORT**

The target port (default: 1900)

**REPORT_LOCATION**

Determines whether to report the UPnP endpoint service advertised by SSDP (default: false)

**THREADS**

The number of concurrent threads (default: 1)

## Scenarios

### Discovering UPnP Devices on a Network

```
msf6 > use auxiliary/scanner/upnp/ssdp_msearch
msf6 auxiliary(scanner/upnp/ssdp_msearch) > set RHOSTS 192.0.2.0/24
RHOSTS => 192.0.2.0/24
msf6 auxiliary(scanner/upnp/ssdp_msearch) > set THREADS 50
THREADS => 50
msf6 auxiliary(scanner/upnp/ssdp_msearch) > run

[*] Sending UPnP SSDP probes to 192.0.2.0->192.0.2.255 (256 hosts)
[*] 192.0.2.10:1900 SSDP Linux/3.10 UPnP/1.0 Router/1.0 | http://192.0.2.10:5000/description.xml | uuid:12345678-1234-1234-1234-123456789012::upnp:rootdevice
[*] 192.0.2.15:1900 SSDP Windows/6.1 UPnP/1.0 | http://192.0.2.15:2869/upnphost/udhisapi.dll?content=uuid:abcd-efgh | uuid:abcd-efgh::upnp:rootdevice
[*] Scanned 256 of 256 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Identifying Vulnerable MiniUPnPd 1.0 Server

```
msf6 auxiliary(scanner/upnp/ssdp_msearch) > set RHOSTS 192.0.2.10
RHOSTS => 192.0.2.10
msf6 auxiliary(scanner/upnp/ssdp_msearch) > run

[*] Sending UPnP SSDP probes to 192.0.2.10->192.0.2.10 (1 hosts)
[+] 192.0.2.10:1900 SSDP Linux/3.10 UPnP/1.0 MiniUPnPd/1.0 | http://192.0.2.10:5000/rootDesc.xml | uuid:12345678-1234-1234-1234-123456789012 | vulns:2 (CVE-2013-0229, CVE-2013-0230)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Identifying Vulnerable Intel SDK / Portable SDK for UPnP

```
msf6 auxiliary(scanner/upnp/ssdp_msearch) > set RHOSTS 192.0.2.20
RHOSTS => 192.0.2.20
msf6 auxiliary(scanner/upnp/ssdp_msearch) > run

[*] Sending UPnP SSDP probes to 192.0.2.20->192.0.2.20 (1 hosts)
[+] 192.0.2.20:1900 SSDP Linux UPnP/1.0 Portable SDK for UPnP devices/1.6.0 | http://192.0.2.20:49152/description.xml | uuid:abcd1234-ab12-ab12-ab12-abcdef123456 | vulns:2 (CVE-2012-5958, CVE-2012-5959)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Scanning with Location Reporting Enabled

```
msf6 auxiliary(scanner/upnp/ssdp_msearch) > set RHOSTS 192.0.2.0/24
RHOSTS => 192.0.2.0/24
msf6 auxiliary(scanner/upnp/ssdp_msearch) > set REPORT_LOCATION true
REPORT_LOCATION => true
msf6 auxiliary(scanner/upnp/ssdp_msearch) > set THREADS 50
THREADS => 50
msf6 auxiliary(scanner/upnp/ssdp_msearch) > run

[*] Sending UPnP SSDP probes to 192.0.2.0->192.0.2.255 (256 hosts)
[*] 192.0.2.10:1900 SSDP Linux/3.10 UPnP/1.0 Router/1.0 | http://192.0.2.10:5000/description.xml | uuid:12345678-1234-1234-1234-123456789012::upnp:rootdevice
[*] 192.0.2.15:1900 SSDP Windows/10 UPnP/1.0 | http://192.0.2.15:2869/upnphost/udhisapi.dll | uuid:device-uuid::upnp:rootdevice
[*] Scanned 256 of 256 hosts (100% complete)
[*] Auxiliary module execution completed
```

### No UPnP Devices Found

```
msf6 auxiliary(scanner/upnp/ssdp_msearch) > set RHOSTS 192.0.2.100
RHOSTS => 192.0.2.100
msf6 auxiliary(scanner/upnp/ssdp_msearch) > run

[*] Sending UPnP SSDP probes to 192.0.2.100->192.0.2.100 (1 hosts)
[*] No SSDP endpoints found.
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Verbose Scanning

```
msf6 auxiliary(scanner/upnp/ssdp_msearch) > set RHOSTS 192.0.2.10
RHOSTS => 192.0.2.10
msf6 auxiliary(scanner/upnp/ssdp_msearch) > set VERBOSE true
VERBOSE => true
msf6 auxiliary(scanner/upnp/ssdp_msearch) > run

[*] Sending UPnP SSDP probes to 192.0.2.10->192.0.2.10 (1 hosts)
[*] 192.0.2.10:1900 - SSDP - sending M-SEARCH probe
[*] 192.0.2.10:1900 SSDP Linux/3.10 UPnP/1.0 Router/1.0 | http://192.0.2.10:5000/description.xml | uuid:12345678-1234-1234-1234-123456789012::upnp:rootdevice
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Checking Metasploit Database for Discovered Services

After a successful scan, you can verify the stored information:

```
msf6 auxiliary(scanner/upnp/ssdp_msearch) > services

Services
========

host         port  proto  name   state  info
----         ----  -----  ----   -----  ----
192.0.2.10   1900  udp    ssdp   open   Linux/3.10 UPnP/1.0 MiniUPnPd/1.0 | http://192.0.2.10:5000/rootDesc.xml | uuid:12345678-1234-1234-1234-123456789012

msf6 auxiliary(scanner/upnp/ssdp_msearch) > vulns

Vulnerabilities
===============

Timestamp  Host         Name                                                                          References
---------  ----         ----                                                                          ----------
2026-10-06 192.0.2.10   MiniUPnPd ProcessSSDPRequest() Out of Bounds Memory Access Denial of Service CVE-2013-0229
2026-10-06 192.0.2.10   MiniUPnPd ExecuteSoapAction memcpy() Remote Code Execution                    CVE-2013-0230
```
