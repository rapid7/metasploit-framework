## HTTP Workflows

HTTP (Hypertext Transfer Protocol), is an application-level protocol for distributed, collaborative, hypermedia information systems.

There are two main ports:
- 80/TCP - HTTP
- 443/TCP - HTTPS (Hypertext Transport Protocol _Secure_) - encrypted using Transport Layer Security or, formerly, Secure Sockets Layer

Note that any port can be used to run an application which communicates via HTTP/HTTPS.

This document is generic advice for running and debugging HTTP based Metasploit modules, but it is best to use a Metasploit module which is specific to the application that you are pentesting. For instance:

```msf
msf6 > search tomcat http
```

### HTTP Examples

Auxiliary modules:

```
use auxiliary/scanner/http/title
run https://example.com
```

Specifying credentials and payload information:

```
use exploit/unix/http/cacti_filter_sqli_rce
run http://admin:pass@application.local/cacti/ lhost=tun0 lport=4444
run 'http://admin:pass with spaces@application.local/cacti/' lhost=tun0 lport=4444
```

Specifying alternative ports:

```
run http://192.168.123.6:9001
```

### HTTP Debugging

You can log all HTTP requests and responses to the Metasploit console with the `HttpTrace` option, as well as enable additional verbose logging:

```
use auxiliary/scanner/http/title
run http://example.com HttpTrace=true verbose=true
```

For instance:

```msf
msf6 > use scanner/http/title
msf6 auxiliary(scanner/http/title) > set RHOSTS 127.0.0.1
RHOSTS => 127.0.0.1
msf6 auxiliary(scanner/http/title) > set HttpTrace true
HttpTrace => true
msf6 auxiliary(scanner/http/title) > run

####################
# Request:
####################
GET / HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)


####################
# Response:
####################
HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/2.7.16
Date: Wed, 16 Dec 2020 01:16:32 GMT
Content-type: text/html; charset=utf-8
Content-Length: 178


<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN"><html>
<title>Directory listing for /</title>
<body>
<h2>Directory listing for /</h2>
<hr>
<ul>
</ul>
<hr>
</body>
</html>


[+] [127.0.0.1:80] [C:200] [R:] [S:SimpleHTTP/0.6 Python/2.7.16] Directory listing for /
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/http/title) >
```

To send all HTTP requests through a proxy, i.e. through Burp Suite:

```
use auxiliary/scanner/http/title
run http://example.com HttpTrace=true verbose=true proxies=HTTP:127.0.0.1:8080
```

### HTTP Credentials

If the module has no `username`/`password` options, for instance to log into an admin portal of a web application etc, then the credentials supplied via a HTTP URI will set the `HttpUsername`/`HttpPassword` options for [HTTP Basic access Authentication](https://en.wikipedia.org/wiki/Basic_access_authentication) purposes.

For instance, in the following module the `username`/`password` options will be set whilst the `HttpUsername`/`HttpPassword` options will not:

```
use exploit/unix/http/cacti_filter_sqli_rce

Module options (exploit/unix/http/cacti_filter_sqli_rce):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   ... Omitted ...
*  PASSWORD   admin            no        Password to login with
   TARGETURI  /cacti/          yes       The URI of Cacti
*  USERNAME   user             yes       User to login with
   ... Omitted ...

check http://admin:user@application.local/cacti/

USERNAME and PASSWORD will be set to 'admin' and 'user'
```

For the following module, as there are no `USERNAME`/`PASSWORD` options, the `HttpUsername`/`HttpPassword` options will be chosen instead for [HTTP Basic access Authentication](https://en.wikipedia.org/wiki/Basic_access_authentication) purposes

```
use exploit/multi/http/tomcat_mgr_deploy
run http://admin:admin@192.168.123.6:8888 HttpTrace=true verbose=true lhost=192.168.123.1
```

Note that the `HttpUsername`/`HttpPassword` may not be present in the `options` output, but can be found in the `advanced` module options:

```
use auxiliary/scanner/http/title
advanced

Module advanced options (auxiliary/scanner/http/title):

   Name                  Current Setting                                    Required  Description
   ----                  ---------------                                    --------  -----------
   DOMAIN                WORKSTATION                                        yes       The domain to use for Windows authentication
   DigestAuthIIS         true                                               no        Conform to IIS, should work for most servers. Only set to false for non-IIS servers
   FingerprintCheck      true                                               no        Conduct a pre-exploit fingerprint verification
   HttpClientTimeout                                                        no        HTTP connection and receive timeout
*  HttpPassword                                                             no        The HTTP password to specify for authentication
   HttpRawHeaders                                                           no        Path to ERB-templatized raw headers to append to existing headers
   HttpTrace             false                                              no        Show the raw HTTP requests and responses
   HttpTraceColors       red/blu                                            no        HTTP request and response colors for HttpTrace (unset to disable)
   HttpTraceHeadersOnly  false                                              no        Show HTTP headers only in HttpTrace
*  HttpUsername                                                             no        The HTTP username to specify for authentication
   SSLVersion            Auto                                               yes       Specify the version of SSL/TLS to be used (Auto, TLS and SSL23 are auto-negotiate) (Accept
                                                                                      ed: Auto, TLS, SSL23, SSL3, TLS1, TLS1.1, TLS1.2)
   ShowProgress          true                                               yes       Display progress messages during a scan
   ShowProgressPercent   10                                                 yes       The interval in percent that progress should be shown
   UserAgent             Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1  no        The User-Agent header to use for all requests
                         )
   VERBOSE               false                                              no        Enable detailed status messages
   WORKSPACE                                                                no        Specify the workspace for this module
```

### HTTP Multiple-Headers
Additional headers can be set via the `HTTPRawHeaders` option.
A file containing a ERB template will be used to append to the headers section of the HTTP request.
An example of an ERB template file is shown below.
```
Header-Name-Here: <%= 'content of header goes here' %>
```

The following output shows leveraging the scraper scanner module with an additional header stored in ```additional_headers.txt```.
```msf
msf6 auxiliary(scanner/http/scraper) > cat additional_headers.txt
[*] exec: cat additional_headers.txt

X-Cookie-Header: <%= 'example-cookie' %>
msf6 auxiliary(scanner/http/scraper) > set HTTPRAWHEADERS additional_headers.txt
HTTPRAWHEADERS => additional_headers.txt
msf6 auxiliary(scanner/http/scraper) > exploit

####################
# Request:
####################
GET / HTTP/1.0
Host: 172.16.0.63:8000
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 13_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15
X-Cookie-Header: example-cookie
```
