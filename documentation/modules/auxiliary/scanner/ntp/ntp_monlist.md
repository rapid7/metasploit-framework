## Vulnerable Application

This module identifies NTP servers which permit "monlist" (or "MON_GETLIST") queries and obtains the recent clients list. The monlist feature, available in NTP versions before 4.2.7p26, allows remote attackers to cause a denial of service through traffic amplification via spoofed requests. Each small monlist request can generate a response that is significantly larger, making it ideal for DDoS amplification attacks.

The vulnerability (CVE-2013-5211) affects NTP servers running ntpd with the monlist command enabled, typically in versions prior to 4.2.7.

### Installation

You can set up a vulnerable NTP server using Docker:

```bash
# Run vulnerable NTP server (ntpd 4.2.6)
docker run -d \
  --name ntp-vuln \
  -p 123:123/udp \
  cturra/ntp:latest

# Or build a custom vulnerable version
mkdir -p ntp_vuln
cd ntp_vuln

cat > Dockerfile << 'EOF'
FROM ubuntu:14.04
RUN apt-get update && \
    apt-get install -y ntp=1:4.2.6.p5+dfsg-3ubuntu2 && \
    rm -rf /var/lib/apt/lists/*

# Configure NTP to allow monlist
RUN echo "disable monitor" > /etc/ntp.conf && \
    sed -i 's/disable monitor/# disable monitor/' /etc/ntp.conf

EXPOSE 123/udp
CMD ["/usr/sbin/ntpd", "-n", "-g", "-u", "ntp:ntp"]
EOF

docker build -t ntp-vulnerable .
docker run -d -p 123:123/udp --name ntp-test ntp-vulnerable

# Generate some traffic to populate the monlist
for i in {1..10}; do
  ntpdate -q 127.0.0.1
  sleep 1
done
```

Alternatively, on a Debian/Ubuntu system:

```bash
# Install older NTP version
apt-get install ntp=1:4.2.6.p5+dfsg-3ubuntu2

# Ensure monlist is not disabled in /etc/ntp.conf
sed -i 's/^disable monitor/# disable monitor/' /etc/ntp.conf

# Restart NTP
service ntp restart
```

## Verification Steps

1. Install and configure the vulnerable NTP server as described above
2. Start msfconsole
3. Do: `use auxiliary/scanner/ntp/ntp_monlist`
4. Do: `set RHOSTS [IP]`
5. Do: `run`
6. You should see the list of recent NTP clients if the server is vulnerable

## Options

**RHOSTS**

The target address range or CIDR identifier

**RPORT**

The target port (default: 123)

**RETRY**

Number of tries to query the NTP server (default: 3)

**SHOW_LIST**

Show the recent clients list (default: false)

**StoreNTPClients**

Store NTP clients as host records in the database (default: false) - Advanced option

**THREADS**

The number of concurrent threads (default: 1)

## Scenarios

### Scanning a Vulnerable NTP Server

```
msf6 > use auxiliary/scanner/ntp/ntp_monlist
msf6 auxiliary(scanner/ntp/ntp_monlist) > set RHOSTS 192.0.2.10
RHOSTS => 192.0.2.10
msf6 auxiliary(scanner/ntp/ntp_monlist) > run

[+] 192.0.2.10:123 NTP monlist request permitted (45 entries)
[+] 192.0.2.10:123 - Vulnerable to NTP Mode 7 monlist DRDoS (CVE-2013-5211): PACKET_LENGTH_IS_987_BYTES
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Scanning with Client List Display

```
msf6 auxiliary(scanner/ntp/ntp_monlist) > set RHOSTS 192.0.2.10
RHOSTS => 192.0.2.10
msf6 auxiliary(scanner/ntp/ntp_monlist) > set SHOW_LIST true
SHOW_LIST => true
msf6 auxiliary(scanner/ntp/ntp_monlist) > run

[+] 192.0.2.10:123 NTP monlist request permitted (8 entries)
[*] 192.0.2.10:123 ["192.0.2.50", 123, "192.0.2.10"]
[*] 192.0.2.10:123 ["192.0.2.51", 123, "192.0.2.10"]
[*] 192.0.2.10:123 ["192.0.2.52", 123, "192.0.2.10"]
[*] 192.0.2.10:123 ["192.0.2.53", 123, "192.0.2.10"]
[*] 192.0.2.10:123 ["192.0.2.54", 123, "192.0.2.10"]
[*] 192.0.2.10:123 ["192.0.2.55", 123, "192.0.2.10"]
[*] 192.0.2.10:123 ["192.0.2.56", 123, "192.0.2.10"]
[*] 192.0.2.10:123 ["192.0.2.57", 123, "192.0.2.10"]
[+] 192.0.2.10:123 - Vulnerable to NTP Mode 7 monlist DRDoS (CVE-2013-5211): PACKET_LENGTH_IS_624_BYTES
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Scanning Multiple NTP Servers

```
msf6 auxiliary(scanner/ntp/ntp_monlist) > set RHOSTS 192.0.2.0/24
RHOSTS => 192.0.2.0/24
msf6 auxiliary(scanner/ntp/ntp_monlist) > set THREADS 50
THREADS => 50
msf6 auxiliary(scanner/ntp/ntp_monlist) > run

[+] 192.0.2.10:123 NTP monlist request permitted (45 entries)
[+] 192.0.2.10:123 - Vulnerable to NTP Mode 7 monlist DRDoS (CVE-2013-5211): PACKET_LENGTH_IS_987_BYTES
[+] 192.0.2.15:123 NTP monlist request permitted (12 entries)
[+] 192.0.2.15:123 - Vulnerable to NTP Mode 7 monlist DRDoS (CVE-2013-5211): PACKET_LENGTH_IS_456_BYTES
[*] 192.0.2.20:123 - Not vulnerable to NTP Mode 7 monlist DRDoS (CVE-2013-5211): ZERO_AMPLIFICATION
[*] Scanned 256 of 256 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Storing NTP Clients in Database

```
msf6 auxiliary(scanner/ntp/ntp_monlist) > set RHOSTS 192.0.2.10
RHOSTS => 192.0.2.10
msf6 auxiliary(scanner/ntp/ntp_monlist) > set SHOW_LIST true
SHOW_LIST => true
msf6 auxiliary(scanner/ntp/ntp_monlist) > set StoreNTPClients true
StoreNTPClients => true
msf6 auxiliary(scanner/ntp/ntp_monlist) > run

[+] 192.0.2.10:123 NTP monlist request permitted (8 entries)
[*] 192.0.2.10:123 ["192.0.2.50", 123, "192.0.2.10"]
[*] 192.0.2.10:123 ["192.0.2.51", 123, "192.0.2.10"]
[*] 192.0.2.10:123 ["192.0.2.52", 123, "192.0.2.10"]
[*] 192.0.2.10:123 ["192.0.2.53", 123, "192.0.2.10"]
[*] 192.0.2.10:123 ["192.0.2.54", 123, "192.0.2.10"]
[*] 192.0.2.10:123 ["192.0.2.55", 123, "192.0.2.10"]
[*] 192.0.2.10:123 ["192.0.2.56", 123, "192.0.2.10"]
[*] 192.0.2.10:123 ["192.0.2.57", 123, "192.0.2.10"]
[*] 192.0.2.10:123 Storing 8 NTP client hosts in the database...
[+] 192.0.2.10:123 - Vulnerable to NTP Mode 7 monlist DRDoS (CVE-2013-5211): PACKET_LENGTH_IS_624_BYTES
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Scanning a Patched NTP Server

```
msf6 auxiliary(scanner/ntp/ntp_monlist) > set RHOSTS 192.0.2.100
RHOSTS => 192.0.2.100
msf6 auxiliary(scanner/ntp/ntp_monlist) > set VERBOSE true
VERBOSE => true
msf6 auxiliary(scanner/ntp/ntp_monlist) > run

[*] 192.0.2.100:123 - Not vulnerable to NTP Mode 7 monlist DRDoS (CVE-2013-5211): ZERO_AMPLIFICATION
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
