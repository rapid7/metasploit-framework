## Vulnerable Application

  This module applies a john the ripper (or hashcat) style .pot file to hashes in the database.
  This will allow very fast cracking of all supported hash types which have already been cracked.

## Verification Steps

  1. Have at least one set of hashes in the database
  2. Start msfconsole
  3. Do: ```use auxiliary/analyze/apply_pot```
  4. Do: ```run```
  5. You should hopefully crack a password.

## Options


   **CONFIG**

   The path to a John config file (JtR option: `--config`).  Default is `metasploit-framework/data/john.conf`

   **JOHN_PATH**

   The absolute path to the John the Ripper executable.  Default behavior is to search `path` for
   `john` and `john.exe`.

   **POT**

   The path to a John POT file (JtR option: `--pot`) to use instead.  The `pot` file is the data file which
   records cracked password hashes.  Kali linux's default location is `/root/.john/john.pot`.
   Default is `~/.msf4/john.pot`.

   **DeleteTempFiles**

   This option will prevent deletion of the wordlist and file containing hashes.  This may be useful for
   running the hashes through john if it wasn't cracked, or for debugging. Default is `false`.

## Scenarios

In this scenario, we fill a bunch of different hash types into the creds db.  You'll need a
.pot file with the cracked hashes, the following can be used:

```
rEK1ecacw.7.c:password
_J9..K0AyUubDrfOgO4s:password
$2a$05$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe:password
yhMEAyLkfWqeQ:se
$1$O3JMY.Tw$AdLnLjQ/5jXF9.MTp3gHv/:password
$5$MnfsQ4iN$ZMTppKN16y/tIsUYs/obHlhdP.Os80yXhTurpBMUbA5:password
$6$zWwwXKNj$gLAOoZCjcr8p/.VgV/FkGC3NX7BsXys3KHYePfuIGMNjY83dVxugPYlxVg/evpcVEJLT/rSwZcDMlVVf/bhf.1:password
0x0100A607BA7C54A24D17B565C59F1743776A10250F581D482DA8:foo
0x01004086CEB6BF932BC4151A1AF1F13CD17301D70816A8886908:toto
0x0100A607BA7C54A24D17B565C59F1743776A10250F581D482DA8B6D6261460D3F53B279CC6913CE747006A2E3254:FOO
0x0200F733058A07892C5CACE899768F89965F6BD1DED7955FE89E1C9A10E27849B0B213B5CE92CC9347ECCB34C3EFADAF2FD99BFFECD8D9150DD6AACB5D409A9D2652A4E0AF16:Password1!
445ff82636a7ba59:probe
*5AD8F88516BD021DD43F171E2C785C69F8E54ADB:tere
O$SIMON#4f8bc1809cb2af77:A
O$SYSTEM#9eedfa0ad26c6d52:THALES
8F2D65FB5547B71C8DA3760F10960428CD307B1C6271691FC55C1F56554A:epsilon
$oracle12c$e3243b98974159cc24fd2c9a8b30ba62e0e83b6ca2fc7c55177c3a7f82602e3bdd17ceb9b9091cf9dad672b8be961a9eac4d344bdba878edc5dcb5899f689ebd8dd1be3f67bff9813a464382381ab36b:epsilon
$dynamic_1034$be86a79bf2043622d58d5453c47d4860$HEX$24556578616d706c65:password
$LM$ac404c4ba2c66533:ASE
$LM$4a3b108f3fa6cb6d:D
$LM$e52cac67419a9a22:PASSWOR
$NT$8846f7eaee8fb117ad06bdd830b7586c:password
```

```
resource (hashes_pot.rb)> creds -d
Credentials
===========

host  origin  service  public  private  realm  private_type  JtR Format
----  ------  -------  ------  -------  -----  ------------  ----------

resource (hashes_pot.rb)> creds add user:des_password hash:rEK1ecacw.7.c jtr:des
resource (hashes_pot.rb)> creds add user:md5_password hash:$1$O3JMY.Tw$AdLnLjQ/5jXF9.MTp3gHv/ jtr:md5
resource (hashes_pot.rb)> creds add user:bsdi_password hash:_J9..K0AyUubDrfOgO4s jtr:bsdi
resource (hashes_pot.rb)> creds add user:sha256_password hash:$5$MnfsQ4iN$ZMTppKN16y/tIsUYs/obHlhdP.Os80yXhTurpBMUbA5 jtr:sha256,crypt
resource (hashes_pot.rb)> creds add user:sha512_password hash:$6$zWwwXKNj$gLAOoZCjcr8p/.VgV/FkGC3NX7BsXys3KHYePfuIGMNjY83dVxugPYlxVg/evpcVEJLT/rSwZcDMlVVf/bhf.1 jtr:sha512,crypt
resource (hashes_pot.rb)> creds add user:blowfish_password hash:$2a$05$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe jtr:bf
resource (hashes_pot.rb)> creds add user:lm_password ntlm:E52CAC67419A9A224A3B108F3FA6CB6D:8846F7EAEE8FB117AD06BDD830B7586C jtr:lm
resource (hashes_pot.rb)> creds add user:nt_password ntlm:AAD3B435B51404EEAAD3B435B51404EE:8846F7EAEE8FB117AD06BDD830B7586C jtr:nt
resource (hashes_pot.rb)> creds add user:mssql05_toto hash:0x01004086CEB6BF932BC4151A1AF1F13CD17301D70816A8886908 jtr:mssql05
resource (hashes_pot.rb)> creds add user:mssql_foo hash:0x0100A607BA7C54A24D17B565C59F1743776A10250F581D482DA8B6D6261460D3F53B279CC6913CE747006A2E3254 jtr:mssql
resource (hashes_pot.rb)> creds add user:mssql12_Password1! hash:0x0200F733058A07892C5CACE899768F89965F6BD1DED7955FE89E1C9A10E27849B0B213B5CE92CC9347ECCB34C3EFADAF2FD99BFFECD8D9150DD6AACB5D409A9D2652A4E0AF16 jtr:mssql12
resource (hashes_pot.rb)> creds add user:mysql_probe hash:445ff82636a7ba59 jtr:mysql
resource (hashes_pot.rb)> creds add user:mysql-sha1_tere hash:*5AD8F88516BD021DD43F171E2C785C69F8E54ADB jtr:mysql-sha1
resource (hashes_pot.rb)> creds add user:simon hash:4F8BC1809CB2AF77 jtr:des,oracle
resource (hashes_pot.rb)> creds add user:SYSTEM hash:9EEDFA0AD26C6D52 jtr:des,oracle
resource (hashes_pot.rb)> creds add user:DEMO hash:'S:8F2D65FB5547B71C8DA3760F10960428CD307B1C6271691FC55C1F56554A;H:DC9894A01797D91D92ECA1DA66242209;T:23D1F8CAC9001F69630ED2DD8DF67DD3BE5C470B5EA97B622F757FE102D8BF14BEDC94A3CC046D10858D885DB656DC0CBF899A79CD8C76B788744844CADE54EEEB4FDEC478FB7C7CBFBBAC57BA3EF22C' jtr:raw-sha1,oracle
resource (hashes_pot.rb)> creds add user:oracle11_epsilon hash:'S:8F2D65FB5547B71C8DA3760F10960428CD307B1C6271691FC55C1F56554A;H:DC9894A01797D91D92ECA1DA66242209;T:23D1F8CAC9001F69630ED2DD8DF67DD3BE5C470B5EA97B622F757FE102D8BF14BEDC94A3CC046D10858D885DB656DC0CBF899A79CD8C76B788744844CADE54EEEB4FDEC478FB7C7CBFBBAC57BA3EF22C' jtr:raw-sha1,oracle
resource (hashes_pot.rb)> creds add user:oracle12c_epsilon hash:'H:DC9894A01797D91D92ECA1DA66242209;T:E3243B98974159CC24FD2C9A8B30BA62E0E83B6CA2FC7C55177C3A7F82602E3BDD17CEB9B9091CF9DAD672B8BE961A9EAC4D344BDBA878EDC5DCB5899F689EBD8DD1BE3F67BFF9813A464382381AB36B' jtr:pbkdf2,oracle12c
resource (hashes_pot.rb)> creds add user:example postgres:md5be86a79bf2043622d58d5453c47d4860
resource (hashes_pot.rb)> use auxiliary/analyze/apply_pot
resource (hashes_pot.rb)> run
[*] Hashes Written out to /tmp/hashes_tmp20190203-16380-1974mdz
[*] Checking bcrypt hashes against pot file
[+] blowfish_password:password
[*] Checking bsdicrypt hashes against pot file
[+] bsdi_password:password
[*] Checking crypt hashes against pot file
Warning: hash encoding string length 46, type id $d
appears to be unsupported on this system; will not load such hashes.
[+] des_password:password
[+] md5_password:password
[+] sha256_password:password
[+] sha512_password:password
[*] Checking descrypt hashes against pot file
[+] des_password:password
[*] Checking lm hashes against pot file
[+] lm_password:password
[*] Checking nt hashes against pot file
[+] lm_password:password
[+] nt_password:password
[*] Checking md5crypt hashes against pot file
[+] md5_password:password
[*] Checking mysql hashes against pot file
[+] mysql_probe:probe
[*] Checking mysql-sha1 hashes against pot file
[+] mysql-sha1_tere:tere
[*] Checking mssql hashes against pot file
[+] mssql_foo:FOO
[*] Checking mssql05 hashes against pot file
[+] mssql05_toto:toto
[+] mssql_foo:foo
[*] Checking mssql12 hashes against pot file
[+] mssql12_Password1!:Password1!
[*] Checking oracle hashes against pot file
[+] simon:A
[+] SYSTEM:THALES
[*] Checking oracle11 hashes against pot file
[+] DEMO:epsilon
[+] oracle11_epsilon:epsilon
[*] Checking oracle12c hashes against pot file
[+] oracle12c_epsilon:epsilon
[*] Checking dynamic_1506 hashes against pot file
[*] Checking dynamic_1034 hashes against pot file
[+] example:password
[*] Auxiliary module execution completed
resource (hashes_pot.rb)> creds
Credentials
===========

host  origin  service  public              private                                                                                                                                                                                                                                                               realm  private_type        JtR Format
----  ------  -------  ------              -------                                                                                                                                                                                                                                                               -----  ------------        ----------
                       des_password        password                                                                                                                                                                                                                                                                     Password            
                       des_password        rEK1ecacw.7.c                                                                                                                                                                                                                                                                Nonreplayable hash  des
                       md5_password        password                                                                                                                                                                                                                                                                     Password            
                       md5_password        $1$O3JMY.Tw$AdLnLjQ/5jXF9.MTp3gHv/                                                                                                                                                                                                                                           Nonreplayable hash  md5
                       bsdi_password       password                                                                                                                                                                                                                                                                     Password            
                       bsdi_password       _J9..K0AyUubDrfOgO4s                                                                                                                                                                                                                                                         Nonreplayable hash  bsdi
                       sha256_password     password                                                                                                                                                                                                                                                                     Password            
                       sha256_password     $5$MnfsQ4iN$ZMTppKN16y/tIsUYs/obHlhdP.Os80yXhTurpBMUbA5                                                                                                                                                                                                                      Nonreplayable hash  sha256,crypt
                       sha512_password     password                                                                                                                                                                                                                                                                     Password            
                       sha512_password     $6$zWwwXKNj$gLAOoZCjcr8p/.VgV/FkGC3NX7BsXys3KHYePfuIGMNjY83dVxugPYlxVg/evpcVEJLT/rSwZcDMlVVf/bhf.1                                                                                                                                                                           Nonreplayable hash  sha512,crypt
                       blowfish_password   password                                                                                                                                                                                                                                                                     Password            
                       blowfish_password   $2a$05$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe                                                                                                                                                                                                                 Nonreplayable hash  bf
                       lm_password         password                                                                                                                                                                                                                                                                     Password            
                       lm_password         e52cac67419a9a224a3b108f3fa6cb6d:8846f7eaee8fb117ad06bdd830b7586c                                                                                                                                                                                                            NTLM hash           nt,lm
                       nt_password         password                                                                                                                                                                                                                                                                     Password            
                       nt_password         aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c                                                                                                                                                                                                            NTLM hash           nt,lm
                       mssql05_toto        toto                                                                                                                                                                                                                                                                         Password            
                       mssql05_toto        0x01004086CEB6BF932BC4151A1AF1F13CD17301D70816A8886908                                                                                                                                                                                                                       Nonreplayable hash  mssql05
                       mssql_foo           foo                                                                                                                                                                                                                                                                          Password            
                       mssql_foo           FOO                                                                                                                                                                                                                                                                          Password            
                       mssql_foo           0x0100A607BA7C54A24D17B565C59F1743776A10250F581D482DA8B6D6261460D3F53B279CC6913CE747006A2E3254                                                                                                                                                                               Nonreplayable hash  mssql
                       mssql12_Password1!  Password1!                                                                                                                                                                                                                                                                   Password            
                       mssql12_Password1!  0x0200F733058A07892C5CACE899768F89965F6BD1DED7955FE89E1C9A10E27849B0B213B5CE92CC9347ECCB34C3EFADAF2FD99BFFECD8D9150DD6AACB5D409A9D2652A4E0AF16                                                                                                                               Nonreplayable hash  mssql12
                       mysql_probe         probe                                                                                                                                                                                                                                                                        Password            
                       mysql_probe         445ff82636a7ba59                                                                                                                                                                                                                                                             Nonreplayable hash  mysql
                       mysql-sha1_tere     tere                                                                                                                                                                                                                                                                         Password            
                       mysql-sha1_tere     *5AD8F88516BD021DD43F171E2C785C69F8E54ADB                                                                                                                                                                                                                                    Nonreplayable hash  mysql-sha1
                       simon               A                                                                                                                                                                                                                                                                            Password            
                       simon               4F8BC1809CB2AF77                                                                                                                                                                                                                                                             Nonreplayable hash  des,oracle
                       SYSTEM              THALES                                                                                                                                                                                                                                                                       Password            
                       SYSTEM              9EEDFA0AD26C6D52                                                                                                                                                                                                                                                             Nonreplayable hash  des,oracle
                       DEMO                epsilon                                                                                                                                                                                                                                                                      Password            
                       DEMO                S:8F2D65FB5547B71C8DA3760F10960428CD307B1C6271691FC55C1F56554A;H:DC9894A01797D91D92ECA1DA66242209;T:23D1F8CAC9001F69630ED2DD8DF67DD3BE5C470B5EA97B622F757FE102D8BF14BEDC94A3CC046D10858D885DB656DC0CBF899A79CD8C76B788744844CADE54EEEB4FDEC478FB7C7CBFBBAC57BA3EF22C         Nonreplayable hash  raw-sha1,oracle
                       oracle11_epsilon    epsilon                                                                                                                                                                                                                                                                      Password            
                       oracle11_epsilon    S:8F2D65FB5547B71C8DA3760F10960428CD307B1C6271691FC55C1F56554A;H:DC9894A01797D91D92ECA1DA66242209;T:23D1F8CAC9001F69630ED2DD8DF67DD3BE5C470B5EA97B622F757FE102D8BF14BEDC94A3CC046D10858D885DB656DC0CBF899A79CD8C76B788744844CADE54EEEB4FDEC478FB7C7CBFBBAC57BA3EF22C         Nonreplayable hash  raw-sha1,oracle
                       oracle12c_epsilon   epsilon                                                                                                                                                                                                                                                                      Password            
                       oracle12c_epsilon   H:DC9894A01797D91D92ECA1DA66242209;T:E3243B98974159CC24FD2C9A8B30BA62E0E83B6CA2FC7C55177C3A7F82602E3BDD17CEB9B9091CF9DAD672B8BE961A9EAC4D344BDBA878EDC5DCB5899F689EBD8DD1BE3F67BFF9813A464382381AB36B                                                                        Nonreplayable hash  pbkdf2,oracle12c
                       example             password                                                                                                                                                                                                                                                                     Password            
                       example             md5be86a79bf2043622d58d5453c47d4860                                                                                                                                                                                                                                          Postgres md5        raw-md5,postgres
```
