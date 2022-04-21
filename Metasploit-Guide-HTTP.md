## HTTP Support

### HTTP Examples

Auxiliary modules:

```
use auxiliary/scanner/http/title
run http://example.com https://example.com https://foo.example.com/bar
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