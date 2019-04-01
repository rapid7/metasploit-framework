## Vulnerable Application

Any instance of memcached with the UDP listener enabled will suffice.

Instructions for testing against Ubuntu 16.04, CentOS 7 and a Dockerized endpoint are provided below.

### Ubuntu 16.04

To a desktop or server Ubuntu 16.04 instance, simply install memcached:

```
apt-get install memcached
```

Then configure it to listen on something other than the loopback interface:

```
sed -i 's/-l 127.0.0.1/#-l 127.0.0.1/g' /etc/memcached.conf
service memcached restart
```

### CentOS 7

To a CentOS 7 instance, simply install and start memcached, as it listens on 0.0.0.0 by default'

```
yum -y install memcached
systemctl start memcached
```

### Docker Install

In memcached 1.5.5 and earlier, the daemon is vulnerable by default.  As such, we can use the
community supported memcached container and simply expose it:

```
docker run -ti --rm -p 11211:11211/udp memcached:1.5.5
```

## Verification Steps


  1. Install the application
  2. Start msfconsole
  3. Do: `use auxiliary/scanner/memcached/memcached_amp`
  4. Do: `set rhosts [IPs]`
  5. Do: `run`
  6. Confirm that the endpoint is discovered vulnerable to the memcached amplification vulnerability.

## Scenarios

### Ubuntu 16.04

Configure memcached as described above.

```
msf5 > use auxiliary/scanner/memcached/memcached_amp
msf5 auxiliary(scanner/memcached/memcached_amp) > set RHOSTS a.b.c.d
RHOSTS => a.b.c.d
msf5 auxiliary(scanner/memcached/memcached_amp) > run

[+] a.b.c.d:11211 - Vulnerable to MEMCACHED amplification: No packet amplification and a 78x, 1163-byte bandwidth amplification
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### CentOS 7

Configure memcached as described above.

```
msf5 > use auxiliary/scanner/memcached/memcached_amp
msf5 auxiliary(scanner/memcached/memcached_amp) > set RHOSTS a.b.c.d
RHOSTS => a.b.c.d
msf5 auxiliary(scanner/memcached/memcached_amp) > run

[+] a.b.c.d:11211 - Vulnerable to MEMCACHED amplification: No packet amplification and a 68x, 1015-byte bandwidth amplification
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Docker

Configure memcached in docker as described above.

```
msf5 > use auxiliary/scanner/memcached/memcached_amp
msf5 auxiliary(scanner/memcached/memcached_amp) > set RHOSTS a.b.c.d
RHOSTS => a.b.c.d
msf5 auxiliary(scanner/memcached/memcached_amp) > run

[+] a.b.c.d:11211 - Vulnerable to MEMCACHED amplification: 2x packet amplification and a 126x, 1880-byte bandwidth amplification
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
