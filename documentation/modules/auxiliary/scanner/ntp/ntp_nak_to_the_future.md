## Vulnerable Application

## Verification Steps

1. Use the supplied Dockerfile to start a vulnerable instance of the application
   1. Build it with: `docker build -t ntpd:4.2.8p3 .`
   1. Run it with: `docker run --rm -it --name ntp-server -p 123:123/udp ntpd:4.2.8p3`
1. Start `msfconsole` and use the module
1. Set the `RHOSTS` value as necessary
1. Run the module and see that the target is vulnerable

### Dockerfile
Use this as `ntp.conf`:

```
# Basic NTP configuration
server 0.pool.ntp.org iburst
server 1.pool.ntp.org iburst
server 2.pool.ntp.org iburst
server 3.pool.ntp.org iburst

driftfile /var/lib/ntp/ntp.drift

# Enable authentication for secure associations
enable auth

# Define trusted keys
trustedkey 1

# Open restrictions for all clients on the local network (example: 192.168.0.0/16)
restrict default kod nomodify notrap
restrict 127.0.0.1
restrict ::1
restrict 192.168.0.0 mask 255.255.0.0 autokey

# Uncomment to allow all clients (use cautiously)
# restrict default kod nomodify notrap
```

Use this as `Dockerfile`:

```
ARG version=4.2.8p3
FROM ubuntu:16.04
ARG version

# Install dependencies
RUN apt-get update && apt-get install -y \
    wget \
    build-essential \
    libcap-dev \
    libssl-dev && \
    apt-get clean

# Download and build NTPD
WORKDIR /tmp
RUN wget https://web.archive.org/web/20240608062853/https://www.eecis.udel.edu/~ntp/ntp_spool/ntp4/ntp-4.2/ntp-$version.tar.gz && \
    tar -xzf ntp-$version.tar.gz && \
    cd ntp-$version && \
    ./configure --prefix=/usr/local --enable-linuxcaps && \
    make && \
    make install && \
    cd .. && \
    rm -rf ntp-$version*

# Add configuration file
COPY ntp.conf /etc/ntp.conf

# Expose NTP port (123)
EXPOSE 123/udp

# Run ntpd
ENTRYPOINT ["/usr/local/bin/ntpd"]
CMD ["-g", "-d", "-d"]
```

## Options

## Scenarios

### Ubuntu 16.04 NTPd 4.2.8p3

```
metasploit-framework (S:0 J:0) auxiliary(scanner/ntp/ntp_nak_to_the_future) > set RHOSTS 192.168.159.128, 192.168.159.10
RHOSTS => 192.168.159.128, 192.168.159.10
metasploit-framework (S:0 J:0) auxiliary(scanner/ntp/ntp_nak_to_the_future) > run
[+] 192.168.159.128:123 - NTP - VULNERABLE: Accepted a NTP symmetric active association
[*] Scanned 1 of 2 hosts (50% complete)
[*] Scanned 1 of 2 hosts (50% complete)
[*] Scanned 1 of 2 hosts (50% complete)
[*] Scanned 1 of 2 hosts (50% complete)
[*] Scanned 1 of 2 hosts (50% complete)
[*] Scanned 2 of 2 hosts (100% complete)
[*] Auxiliary module execution completed
metasploit-framework (S:0 J:0) auxiliary(scanner/ntp/ntp_nak_to_the_future) >
```
