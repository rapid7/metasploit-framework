## Vulnerable Application

Any instance of memcached with the UDP listener enabled will suffice.

Instructions for testing against CentOS 7 and a Dockerized endpoint are provided below.

### CentOS 7

To a CentOS 7 instance, simply install and start memcached, as it listens on 0.0.0.0 by default'

```
yum -y install memcached
systemctl start memcached
```

### Docker Install

In memcached 1.5.5 and earlier, the daemon is affected by default.  As such, we can use the
community supported memcached container and simply expose it:

```
docker run -ti --rm -p 11211:11211/udp memcached:1.5.5
```

## Verification Steps


  1. Install the application
  2. Start msfconsole
  3. Do: `use auxiliary/scanner/memcached/memcached_udp_version`
  4. Do: `set rhosts [IPs]`
  5. Do: `run`
  6. Confirm that the endpoint is discovered to be running memcached and the version is displayed

## Scenarios

### CentOS 7

Configure memcached as described above.

```
msf5 > use auxiliary/scanner/memcached/memcached_udp_version
msf5 auxiliary(scanner/memcached/memcached_udp_version) > set RHOSTS a.b.c.d
RHOSTS => a.b.c.d
msf5 auxiliary(scanner/memcached/memcached_udp_version) > run

[+] a.b.c.d:11211/udp memcached version 1.4.15
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Docker

Configure memcached in docker as described above.

```
msf5 > use auxiliary/scanner/memcached/memcached_udp_version
msf5 auxiliary(scanner/memcached/memcached_udp_version) > set RHOSTS a.b.c.d
RHOSTS => a.b.c.d
msf5 auxiliary(scanner/memcached/memcached_udp_version) > run

[+] a.b.c.d:11211/udp memcached version 1.5.5
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
