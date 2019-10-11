## Description
  This module attempts to authenticate against a Wordpress-site (via 
  XMLRPC) using username and password combinations indicated by the 
  `USER_FILE`, `PASS_FILE`, and `USERPASS_FILE` options.

## References
* [https://codex.wordpress.org/XML-RPC_Support](https://codex.wordpress.org/XML-RPC_Support)
* [http://www.ethicalhack3r.co.uk/security/introduction-to-the-wordpress-xml-rpc-api/](http://www.ethicalhack3r.co.uk/security/introduction-to-the-wordpress-xml-rpc-api/)

## Vulnerable Application

### Setup using Docksal
Install [Docksal](https://docksal.io/)

Create a new WordPress installation using `fin project create`

```
fin project create
1. Name your project (lowercase alphanumeric, underscore, and hyphen): msf-wp

2. What would you like to install?
  PHP based
    1.  Drupal 8
    2.  Drupal 8 (Composer Version)
    3.  Drupal 7
    4.  Wordpress
    5.  Magento
    6.  Laravel
    7.  Symfony Skeleton
    8.  Symfony WebApp
    9.  Grav CMS
    10. Backdrop CMS

  Go based
    11. Hugo

  JS based
    12. Gatsby JS
    13. Angular

  HTML
    14. Static HTML site

Enter your choice (1-14): 4

Project folder:   /home/weh/dev/msf-wp
Project software: Wordpress
Project URL:      http://msf-wp.docksal

Do you wish to proceed? [y/n]: y
Cloning repository...
Cloning into 'msf-wp'...
...
3. Installing site
 Step 1  Initializing stack...
Removing containers...
...
Starting services...
Creating network "msf-wp_default" with the default driver
Creating volume "msf-wp_cli_home" with default driver
Creating volume "msf-wp_project_root" with local driver
Creating volume "msf-wp_db_data" with default driver
Creating msf-wp_db_1  ... done
Creating msf-wp_cli_1 ... done
Creating msf-wp_web_1 ... done
Connected vhost-proxy to "msf-wp_default" network.
Waiting for project stack to become ready...
 Step 2  Initializing site...
 Step 2  Generating wp-config.php...
Success: Generated 'wp-config.php' file.
 Step 3  Installing site...
msmtp: envelope-from address is missing
Success: WordPress installed successfully.

Open http://msf-wp.docksal in your browser to verify the setup.
Admin panel: http://msf-wp.docksal/wp-admin. User/password: admin/admin  
 DONE!  Completed all initialization steps.
```

## Verification Steps

1. Do: ```use auxiliary/scanner/http/wordpress_xmlrpc_login```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set VHOST [HOSTNAME]```
4. Do: ```set USERNAME [user]```
5. Do: ```set PASSWORD [pass]```
6. Do: ```run```

## Options

**USERNAME**

A specific username to authenticate as

**USER_FILE**

File containing usernames, one per line

**PASSWORD**

A specific password to authenticate with

**PASS_FILE**

File containing passwords, one per line

**USERPASS_FILE**

File containing users and passwords separated by space, one pair per line

**USER_AS_PASS**

Try the username as the password for all users (default: `false`)


## Scenarios

### Wordpress 5.2 running in Docksal

Follow the Instructions above to setup the Docksal Containers.

```
msf5 > use auxiliary/scanner/http/wordpress_xmlrpc_login 
msf5 auxiliary(scanner/http/wordpress_xmlrpc_login) > set RHOST msf-wp.docksal
RHOST => msf-wp.docksal
msf5 auxiliary(scanner/http/wordpress_xmlrpc_login) > set VHOST msf-wp.docksal
VHOST => msf-wp.docksal
msf5 auxiliary(scanner/http/wordpress_xmlrpc_login) > set USERNAME admin
USERNAME => admin
msf5 auxiliary(scanner/http/wordpress_xmlrpc_login) > set PASSWORD admin
PASSWORD => admin
msf5 auxiliary(scanner/http/wordpress_xmlrpc_login) > run

[*] 192.168.64.100:80    :/xmlrpc.php - Sending Hello...
[+] 192.168.64.100:80 - XMLRPC enabled, Hello message received!
[*] Starting XML-RPC login sweep...
[+] 192.168.64.100:80 - Success: 'admin:admin'
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf5 auxiliary(scanner/http/wordpress_xmlrpc_login) > 

```


### Wordpress 5.2 with disabled or protected XMLRPC

You may see this message also, if you forgot to set the `VHOST` option.


```
msf5 > use auxiliary/scanner/http/wordpress_xmlrpc_login 
msf5 auxiliary(scanner/http/wordpress_xmlrpc_login) > set RHOST msf-wp.docksal
RHOST => msf-wp.docksal
msf5 auxiliary(scanner/http/wordpress_xmlrpc_login) > set USERNAME admin
USERNAME => admin
msf5 auxiliary(scanner/http/wordpress_xmlrpc_login) > set PASSWORD admin
PASSWORD => admin
msf5 auxiliary(scanner/http/wordpress_xmlrpc_login) > run

[*] 192.168.64.100:80    :/xmlrpc.php - Sending Hello...
[-] XMLRPC is not enabled! Aborting
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf5 auxiliary(scanner/http/wordpress_xmlrpc_login) > 

```
