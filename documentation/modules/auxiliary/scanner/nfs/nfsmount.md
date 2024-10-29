## Vulnerable Application

NFS is very common, and this scanner searches for a mis-configuration, not a vulnerable software version.
Installation instructions for NFS can be found for every operating system.
The [Ubuntu](https://ubuntu.com/server/docs/service-nfs)
instructions can be used as an example for installing and configuring NFS.  The
following was done on Kali linux:

1. `apt-get install nfs-kernel-server`
2. Create folders to share and add them to exports (adjust 192.168.1.x as needed):
```
mkdir /tmp/star
echo "/tmp/star    *(rw,no_subtree_check)" >> /etc/exports
mkdir /tmp/not_us_hostname
echo "/tmp/not_us_hostname    foo(rw,no_subtree_check)" >> /etc/exports
mkdir /tmp/us_hostname
echo "/tmp/us_hostname    bar(rw,no_subtree_check)" >> /etc/exports
mkdir /tmp/not_us_ip
echo "/tmp/not_us_ip    1.1.1.1(rw,no_subtree_check)" >> /etc/exports
mkdir /tmp/us_ip
echo "/tmp/us_ip    192.168.1.111(rw,no_subtree_check)" >> /etc/exports
mkdir /tmp/not_us_subnet
echo "/tmp/not_us_subnet    1.1.1.1/24(rw,no_subtree_check)" >> /etc/exports
mkdir /tmp/us_subnet
echo "/tmp/us_subnet    192.168.1.1/24(rw,no_subtree_check)" >> /etc/exports
mkdir /tmp/not_us_netmask
echo "/tmp/not_us_netmask    1.1.1.1/255.255.255.0(rw,no_subtree_check)" >> /etc/exports
mkdir /tmp/us_netmask
echo "/tmp/us_netmask    192.168.1.1/255.255.255.0(rw,no_subtree_check)" >> /etc/exports
mkdir /tmp/empty
echo "/tmp/empty    (rw,no_subtree_check)" >> /etc/exports
```
3. Restart the service: `service nfs-kernel-server restart`

## Options

### PROTOCOL
Which networking protocol to use. Options are `udp` and `tcp`. Defaults to `udp`.

### LHOST
IP to match shares against if `Mountable` is true. Defaults to the detected local IP address.

### HOSTNAME
Hostname to match shares against if `Mountable` is true. Defaults to `` (empty string)

## Advanced Options

### Mountable

Determine if an export is mountable based on `LHOST` and `HOSTNAME`. Defaults to `true`. Pre 2022 behavior was `false`

## Verification Steps

1. Install and configure NFS
2. Start msfconsole
3. Do: `use auxiliary/scanner/nfs/nfsmount`
4. Do: `run`

## Scenarios

A run against the configuration from these docs

```
msf > use auxiliary/scanner/nfs/nfsmount
msf auxiliary(nfsmount) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf auxiliary(nfsmount) > run

[+] 127.0.0.1:111       - 127.0.0.1 NFS Export: /tmp/empty [*]
[+] 127.0.0.1:111       - 127.0.0.1 NFS Export: /tmp/star [*]
[+] 127.0.0.1:111       - 127.0.0.1 NFS Export: /tmp/us_netmask [10.1.1.1/255.255.255.0]
[*] 127.0.0.1:111       - 127.0.0.1 NFS Export: /tmp/not_us_netmask [1.1.1.1/255.255.255.0]
[+] 127.0.0.1:111       - 127.0.0.1 NFS Export: /tmp/us_subnet [10.1.1.1/24]
[*] 127.0.0.1:111       - 127.0.0.1 NFS Export: /tmp/not_us_subnet [1.1.1.1/24]
[+] 127.0.0.1:111       - 127.0.0.1 NFS Export: /tmp/us_ip [192.168.1.111]
[*] 127.0.0.1:111       - 127.0.0.1 NFS Export: /tmp/not_us_ip [1.1.1.1]
[*] 127.0.0.1:111       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Another example can be found at this [source](http://bitvijays.github.io/blog/2016/03/03/learning-from-the-field-basic-network-hygiene/):

```
[*] Scanned  24 of 240 hosts (10% complete)
[+] 10.10.xx.xx NFS Export: /data/iso [0.0.0.0/0.0.0.0]
[*] Scanned  48 of 240 hosts (20% complete)
[+] 10.10.xx.xx NFS Export: /DataVolume/Public [*]
[+] 10.10.xx.xx NFS Export: /DataVolume/Download [*]
[+] 10.10.xx.xx NFS Export: /DataVolume/Softshare [*]
[*] Scanned  72 of 240 hosts (30% complete)
[+] 10.10.xx.xx NFS Export: /var/ftp/pub [10.0.0.0/255.255.255.0]
[*] Scanned  96 of 240 hosts (40% complete)
[+] 10.10.xx.xx NFS Export: /common []
```

## Confirming

Since NFS has been around since 1989, with modern NFS(v4) being released in 2000, there are many tools which can also be used to
verify this configuration issue.
The following are other industry tools which can also be used.

### [nmap](https://nmap.org/nsedoc/scripts/nfs-showmount.html)

```
nmap -p 111 --script=nfs-showmount 127.0.0.1

Starting Nmap 7.40 ( https://nmap.org ) at 2017-02-12 19:41 EST
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000037s latency).
PORT    STATE SERVICE
111/tcp open  rpcbind
| nfs-showmount: 
|   /tmp/empty *
|   /tmp/star *
|   /tmp/us_netmask 10.1.1.1/255.255.255.0
|   /tmp/not_us_netmask 1.1.1.1/255.255.255.0
|   /tmp/us_subnet 10.1.1.1/24
|   /tmp/not_us_subnet 1.1.1.1/24
|   /tmp/us_ip 192.168.1.111
|_  /tmp/not_us_ip 1.1.1.1

Nmap done: 1 IP address (1 host up) scanned in 0.32 seconds
```

### [showmount](https://packages.debian.org/sid/amd64/nfs-common/filelist)

showmount is a part of the `nfs-common` package for debian.

```
showmount -e 127.0.0.1
Export list for 127.0.0.1:
/tmp/empty          *
/tmp/star           *
/tmp/us_netmask     10.1.1.1/255.255.255.0
/tmp/not_us_netmask 1.1.1.1/255.255.255.0
/tmp/us_subnet      10.1.1.1/24
/tmp/not_us_subnet  1.1.1.1/24
/tmp/us_ip          192.168.1.111
/tmp/not_us_ip      1.1.1.1
```

## Exploitation

Exploiting this mis-configuration is trivial, however exploitation doesn't necessarily give access (command execution) to the system.
If a share is mountable, ie you either are the IP listed in the filter (or could assume it through a DoS),
or it is open (*), mounting is trivial.
The following instructions were written for Kali linux.

1. Create a new directory to mount the remote volume to: `mkdir /mnt/remote`
2. Use `mount` to link the remote volume to the local folder: `mount -t nfs 127.0.0.1:/tmp/open_share /mnt/remote`

The mount and its writability can now be tested:

1. Write a file:  `echo "hello" > /mnt/remote/test`
2. The remote end now has the file locally:
```
cat /tmp/open_share/test 
hello
```

1. To unmount: `umount /mnt/remote`

At this point, its time to hope for a file of value.  Maybe code with hardcoded credentials, a `passwords.txt`, or an `id_rsa`.
