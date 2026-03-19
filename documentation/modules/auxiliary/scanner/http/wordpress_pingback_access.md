# WordPress Pingback Locator

## Description

This module scans WordPress sites to determine whether the XML-RPC pingback API is enabled. If enabled, the feature can be abused to perform port scanning or amplification attacks via the target server.

This vulnerability is associated with CVE-2013-0235 and was fixed in WordPress 3.5.1.

## Module Name

auxiliary/scanner/http/wordpress_pingback_access

## Authors

- Thomas McCarthy (smilingraccoon)
- Brandon McCann (zeknox)
- Christian Mehlmauer

## References

- [CVE-2013-0235](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-0235)
- [Bugtraq thread](https://bugtraq.securityfocus.com/archive/1/525045/30/30/threaded)
- [Introduction to the WordPress XML-RPC API](http://www.ethicalhack3r.co.uk/security/introduction-to-the-wordpress-xml-rpc-api/)
- [WordpressPingbackPortScanner](https://github.com/FireFart/WordpressPingbackPortScanner)

## Usage

```
use auxiliary/scanner/http/wordpress_pingback_access
set RHOSTS target.com
set TARGETURI /
run
```


## Options

- `RHOSTS`: Target host(s)
- `TARGETURI`: Path to the WordPress installation (default: `/`)
- `NUM_REDIRECTS`: Number of HTTP redirects to follow (default: `10`)

## Expected Output

- Indicates whether the `X-Pingback` header is present
- Confirms if pingback is enabled or disabled
- Displays vulnerable blog post endpoints if found
