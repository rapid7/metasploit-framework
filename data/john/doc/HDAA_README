                  HTTP Digest access authentication
                  ---------------------------------



- How to create the password string :
-------------------------------------


user:$MAGIC$response$user$realm$method$uri$nonce$nonceCount$ClientNonce$qop

'$' is use as separator, you can change it in HDAA_fmt.c


Example of password string :

user:$response$679066476e67b5c7c4e88f04be567f8b$user$myrealm$GET$/$8c12bd8f728afe56d45a0ce846b70e5a$00000001$4b61913cec32e2c9$auth

Here the magic is '$response$'





- Demonstration :
-----------------

Tested on a : AMD Athlon(tm) 64 Processor 3000+

$ cat ./htdigest
moi:$response$faa6cb7d676e5b7c17fcbf966436aa0c$moi$myrealm$GET$/$af32592775d27b1cd06356b3a0db9ddf$00000001$8e1d49754a25aea7$auth
user:$response$679066476e67b5c7c4e88f04be567f8b$user$myrealm$GET$/$8c12bd8f728afe56d45a0ce846b70e5a$00000001$4b61913cec32e2c9$auth

$ ./john ./htdigest
Loaded 2 password hashes with 2 different salts (HTTP Digest access authentication [HDAA-MD5])
kikou            (moi)
nocode           (user)
guesses: 2  time: 0:00:01:27 (3)  c/s: 670223  trying: nocode
