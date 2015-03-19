The Exim GHOST buffer overflow is a vulnerability found by researchers from Qualys. On March 17th 2015, Qualys released an exploit module demonstrating the exploitability of this flaw, which is now exim_gethostbyname_bof.rb in Metasploit Framework.

When Qualys released the exploit, it included a lot of technical details for debugging and usage purposes. We decided to put all that here in a more readable format.

## What is "GHOST"

This is a heap based buffer overflow found in GNU C Library's **g**et**host**byname functions since glibc-2.2 (November 10, 2000), which is part of the Linux operating system, such as: Debian, Red Hat, CentOS, and Ubuntu.

## Exploitable Requirements

**On the server-side (victim):**

* glibc-2.6 - glibc-2.17: The exploit depends on the newer versions' fd_nextsize (a member of the malloc_chunk structure) to remotely obtain the address of Exim's smtp_cmd_buffer in the heap.
* Exim server. The first exploitable version is Exim-4.77, maybe older. The exploit depends on the newer versions' 16-KB smtp_cmd_buffer to reliably set up the heap as described in the advisory.
* The Exim server also must enable helo_try_verify_hosts or helo_verify_hosts in the /etc/exim4/exim4.conf.template file. The "verify = helo" ACL might be exploitable too, but the attack vector isn't as reliable, therefore not supported by the module.

For testing purposes, if you need to find a vulnerable system, you can try Debian 7:
http://ftp.cae.tntech.edu/debian-cd/dvd/debian-7.7.0-i386-DVD-1.iso

**On the attacker's side:**

* The attacker's IPv4 address must have both forward and reverse DNS entries that match each other (Forward-Confirmed reverse DNS). For testing purposes, you can also edit the server's /etc/hosts file to meet this requirement.

## Troubleshooting

If the exim_gethostbyname_bof.rb module has failed on you:

| Failure  | Explanation |
| -------- | ----------- |
| bad SENDER_HOST_ADDRESS (nil) | The SENDER_HOST_ADDRESS option was not specified |
| bad SENDER_HOST_ADDRESS (not in IPv4 dotted-decimal notation) | The SENDER_HOST_ADDRESS option was specified, but not in IPv4 dotted-decimal notation |
| bad SENDER_HOST_ADDRESS (helo_verify_hosts) | The SENDER_HOST_ADDRESS option does not match the IPv4 address of the SMTP client (Metasploit), as seen by the SMTP server (Exim). |
| bad SENDER_HOST_ADDRESS (no FCrDNS) | the IPv4 address of the SMTP client (Metasploit) has no Forward-Confirmed reverse DNS. |
| not vuln? old glibc? (no leaked_arch) | the remote Exim server is either not vulnerable, or not exploitable (glibc versions older than glibc-2.6 have no fd_nextsize member in their malloc_chunk structure). |
| NUL, CR, LF in addr? (no leaked_addr) | Exim's heap address contains bad characters (NUL, CR, LF) and was therefore mangled during the information leak; this exploit is able to reconstruct most of these addresses, but not all (worst-case probability is ~1/85, but could be further improved). |
| Brute-force SUCCESS" followed by a nil reply, but no shell | the remote Unix command was executed, but spawned a bind-shell or a reverse-shell that failed to connect (maybe because of a firewall, or a NAT, etc). |
| Brute-force SUCCESS" followed by a non-nil reply, and no shell | The remote Unix command was executed, but failed to spawn the shell (maybe because the setsid command doesn't exist, or awk isn't gawk, or netcat doesn't support the -6 or -e option, or telnet doesn't support the -z option, etc). |

## References:

* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-0235
* https://community.qualys.com/blogs/laws-of-vulnerabilities/2015/03/17/ghost-remote-code-execution-exploit
* https://www.qualys.com/research/security-advisories/GHOST-CVE-2015-0235.txt?_ga=1.171218720.101498705.1426692159
* https://www.qualys.com/research/security-advisories/GHOST-CVE-2015-0235.txt?_ga=1.136230833.101498705.1426692159