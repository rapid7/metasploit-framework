## Vulnerable Application

RPC Portmapper, or more recently renamed to rpcbind, is fairly common and this scanner searches for its existance.  The idea behind rpcbind was to create a
'directory' that could be asked where a service is running (port).  Having this single port/service be queryable meant, the services being managed by rpcbind
could actually be running on any port or protocol, and rpdbind would be in charge of letting clients know where they were. This is more or less an outdated
model/service, and NFS is arguably the most popular service still utilizing rpcbind.  The following was done on Kali linux:

  1. Install rpcbind: `apt-get install rpcbind`
  2. Now now have `rpcbind`, but this gives us minimal services running on it.  You may want to install additional:
    * NIS: `apt-get install nis`
      * Start the service: `ypserv`
    * NFS: `apt-get install nfs-kernel-server`
  3. Just to be safe, restart rpcbind: `service rpcbind restart`

## Verification Steps

  1. Install and configure rpcbind
  2. Start msfconsole
  3. Do: `use auxiliary/scanner/misc/sunrpc_portmapper`
  4. Do: `run`

## Scenarios

  A run against the configuration from these docs

  ```
    msf > use auxiliary/scanner/misc/sunrpc_portmapper
    msf auxiliary(sunrpc_portmapper) > set rhosts 127.0.0.1
    rhosts => 127.0.0.1
    msf auxiliary(sunrpc_portmapper) > run
    
    [+] 127.0.0.1:111         - SunRPC Programs for 127.0.0.1
    =============================
    
     Name      Number  Version  Port   Protocol
     ----      ------  -------  ----   --------
     mountd    100005  1        60153  udp
     mountd    100005  1        39027  tcp
     mountd    100005  2        47725  udp
     mountd    100005  2        53055  tcp
     mountd    100005  3        49015  udp
     mountd    100005  3        47033  tcp
     nfs       100003  3        2049   tcp
     nfs       100003  4        2049   tcp
     nfs       100003  3        2049   udp
     nfs       100003  4        2049   udp
     nfs_acl   100227  3        2049   tcp
     nfs_acl   100227  3        2049   udp
     nlockmgr  100021  1        40970  udp
     nlockmgr  100021  3        40970  udp
     nlockmgr  100021  4        40970  udp
     nlockmgr  100021  1        42279  tcp
     nlockmgr  100021  3        42279  tcp
     nlockmgr  100021  4        42279  tcp
     rpcbind   100000  4        111    tcp
     rpcbind   100000  3        111    tcp
     rpcbind   100000  2        111    tcp
     rpcbind   100000  4        111    udp
     rpcbind   100000  3        111    udp
     rpcbind   100000  2        111    udp
     ypserv    100004  2        707    udp
     ypserv    100004  1        707    udp
     ypserv    100004  2        708    tcp
     ypserv    100004  1        708    tcp
    
    [*] Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed
  ```

## Confirming

Since rpc port mapper has been around since 1995, there are many tools which can also query it.
The following are other industry tools which can also be used.

### [nmap](https://nmap.org/nsedoc/scripts/rpcinfo.html)

```
nmap -p 111 --script=rpcinfo 127.0.0.1

Starting Nmap 7.40 ( https://nmap.org ) at 2017-02-13 22:57 EST
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000043s latency).
PORT    STATE SERVICE
111/tcp open  rpcbind
| rpcinfo: 
|   program version   port/proto  service
|   100000  2,3,4        111/tcp  rpcbind
|   100000  2,3,4        111/udp  rpcbind
|   100003  3,4         2049/tcp  nfs
|   100003  3,4         2049/udp  nfs
|   100004  1,2          707/udp  ypserv
|   100004  1,2          708/tcp  ypserv
|   100005  1,2,3      47033/tcp  mountd
|   100005  1,2,3      49015/udp  mountd
|   100021  1,3,4      40970/udp  nlockmgr
|   100021  1,3,4      42279/tcp  nlockmgr
|   100227  3           2049/tcp  nfs_acl
|_  100227  3           2049/udp  nfs_acl
```

### rpcinfo

This is the standard package included with rpcbind to query the rpc interface.

```
rpcinfo -p 127.0.0.1
   program vers proto   port  service
    100000    4   tcp    111  portmapper
    100000    3   tcp    111  portmapper
    100000    2   tcp    111  portmapper
    100000    4   udp    111  portmapper
    100000    3   udp    111  portmapper
    100000    2   udp    111  portmapper
    100005    1   udp  60153  mountd
    100005    1   tcp  39027  mountd
    100005    2   udp  47725  mountd
    100005    2   tcp  53055  mountd
    100005    3   udp  49015  mountd
    100005    3   tcp  47033  mountd
    100003    3   tcp   2049  nfs
    100003    4   tcp   2049  nfs
    100227    3   tcp   2049
    100003    3   udp   2049  nfs
    100003    4   udp   2049  nfs
    100227    3   udp   2049
    100021    1   udp  40970  nlockmgr
    100021    3   udp  40970  nlockmgr
    100021    4   udp  40970  nlockmgr
    100021    1   tcp  42279  nlockmgr
    100021    3   tcp  42279  nlockmgr
    100021    4   tcp  42279  nlockmgr
    100004    2   udp    707  ypserv
    100004    1   udp    707  ypserv
    100004    2   tcp    708  ypserv
    100004    1   tcp    708  ypserv
```
