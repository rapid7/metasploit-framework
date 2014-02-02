This page lists the keys in use by Metasploit committers.

| Account | E-mail | Gist | MIT |
| ---------- | ------ | ------------ | ------- |
| [@jvazquez-r7](https://github.com/jvazquez-r7) | juan.vazquez@metasploit.com | [B9352D83](https://gist.github.com/jvazquez-r7/7321429) | [0x38D99152B9352D83](http://pgp.mit.edu:11371/pks/lookup?op=vindex&search=0x38D99152B9352D83) |
| [@jvennix-r7](https://github.com/jvennix-r7) | joev@metasploit.com | [3E85A2B0](https://gist.github.com/jvennix-r7/7572570) | [0x127b05fb3e85a2b0](http://pgp.mit.edu:11371/pks/lookup?op=vindex&search=0x127b05fb3e85a2b0) |
| [@kernelsmith](https://github.com/kernelsmith) | kernelsmith@metasploit.com | [92EC0809](https://gist.github.com/kernelsmith/0e9563d2fb52f16765b5) |[0xf2c611dc92ec0809](http://pgp.mit.edu/pks/lookup?op=vindex&search=0xF2C611DC92EC0809) |
| [@limhoff-r7](https://github.com/limhoff-r7) | luke_imhoff@rapid7.com | [B33356F8](https://gist.github.com/limhoff-r7/8714106) | [0x5B1FB01FB33356F8](http://pgp.mit.edu/pks/lookup?op=vindex&search=0x5B1FB01FB33356F8) |
| [@Meatballs1](https://github.com/Meatballs1) | eat_meatballs@hotmail.co.uk | [1F2F8B38](https://gist.github.com/Meatballs1/6732257) | [0x5380EAF01F2F8B38](http://pgp.mit.edu:11371/pks/lookup?op=vindex&search=0x5380EAF01F2F8B38) |
| [@OJ](https://github.com/OJ) | oj@buffered.io | [1FAA5749](https://gist.github.com/OJ/8d4533352afd1586526d) | [0x49EEE7511FAA5749](http://pgp.mit.edu:11371/pks/lookup?op=vindex&search=0x49EEE7511FAA5749) |
| [@scriptjunkie1](https://github.com/scriptjunkie) | scriptjunkie@scriptjunkie.us | [591C6B5D](https://gist.github.com/scriptjunkie/7280483) | [0xE0F49052591C6B5D](http://pgp.mit.edu:11371/pks/lookup?op=vindex&search=0xE0F49052591C6B5D) |
| [@todb-r7](https://github.com/todb-r7) | tod_beardsley@rapid7.com | [ADB9F193](https://gist.github.com/todb-r7/7269765) | [0x1EFFB682ADB9F193](http://pgp.mit.edu:11371/pks/lookup?op=vindex&search=0x1EFFB682ADB9F193) |
| [@wchen-r7](https://github.com/wchen-r7) | wei_chen@rapid7.com | [F06F730B](https://gist.github.com/wchen-r7/0e0269d9ff0afc1ca7a5) | [0x2384DB4EF06F730B](http://pgp.mit.edu:11371/pks/lookup?op=vindex&search=0x2384DB4EF06F730B) |
| [@wvu-r7](https://github.com/wvu-r7) | william_vu@rapid7.com | [C1629024](https://gist.github.com/wvu-r7/7049076) | [0xE761DCB4C1629024](http://pgp.mit.edu:11371/pks/lookup?op=vindex&search=0xE761DCB4C1629024)|

# Signing criteria

In order to get @todb-r7 to sign your key, you should:

 * tell him your Key ID over some mechanism (IRC, Skype, etc)
 * post it to https://gist.github.com under your GitHub account

If you are near by, he'll ask you to confirm your Key ID in meatspace, using unique biometric and contextual data to verify your identity. If not, he'll e-mail you, using that key and a known e-mail address, and expect your response.

This constitutes verification that your key is, in fact, yours. Please set a reasonable expiration date (18 months is recommended), key length (2048 or better), and use good sense when managing your private key availability.

# Signing HOWTO

Signing merges and commits is easy and fun. Generate a signing key, if you don't have one already, using your favorite PGP/GPG interface (I use `gpg --gen-key`). Then add this to your $HOME/.gitconfig:

````
[user]
  name = Your Name
  email = your_email@example.com
  signingkey = DEADBEEF # Must match name and email exactly!
[alias]
  c = commit -S --edit
  m = merge -S --no-ff --edit
````

Using `git c` and `git m` from now on will sign every commit with your `DEADBEEF` key.