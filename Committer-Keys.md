This page lists the keys in use by [Metasploit committers][msf-committers] and
can be used to verify merge commits made to https://github.com/rapid7/metasploit-framework.

# Keybase.io identities

Keybase.io is used by Metasploit as an easy way to verify identities of committers.

If you're a committer on metasploit-framework, and you need an invite, just ask.

| Github Username                                   | Keybase.io Username                                |
| ------------------------------------------------- | -------------------------------------------------- |
| [@acammack-r7](https://github.com/acammack-r7)    | [acammackr7](https://keybase.io/acammackr7)        |
| [@bcoles](https://github.com/bcoles)              | [bcoles](https://keybase.io/bcoles)                |
| [@busterb](https://github.com/busterb)            | [busterb](https://keybase.io/busterb)              |
| [@bwatters-r7](https://github.com/bwatters-r7)    | [bwatters](https://keybase.io/bwatters)            |
| [@ccondon-r7](https://github.com/ccondon-r7)      | [catc0n](https://keybase.io/catc0n)                |
| [@cdelafuente-r7](https://github.com/cdelafuente-r7)|[cdelafuente](https://keybase.io/cdelafuente)    |
| [@chiggins](https://github.com/chiggins)          | [chiggins](https://keybase.io/chiggins)            |
| [@egypt](https://github.com/egypt)                | [egypt](https://keybase.io/egypt)                  |
| [@FireFart](https://github.com/FireFart)          | [firefart](https://keybase.io/firefart)            |
| [@Green-m](https://github.com/Green-m)            | [green-m](https://keybase.io/green_m)              |
| [@h00die](https://github.com/h00die)              | [h00die](https://keybase.io/h00die)                |
| [@jbarnett-r7](https://github.com/jbarnett-r7)    | [jmbarnett](https://keybase.io/jmbarnett)          |
| [@jmartin-r7](https://github.com/jmartin-r7)      | [jmartinr7](https://keybase.io/jmartinr7)          |
| [@lsato-r7](https://github.com/lsato-r7)          | [louissato](https://keybase.io/lsato)              |
| [@Meatballs1](https://github.com/Meatballs1)      | [meatballs](https://keybase.io/meatballs)          |
| [@mkienow-r7](https://github.com/mkienow-r7)      | [inokii](https://keybase.io/inokii)                |
| [@mubix](https://github.com/mubix)                | [mubix](https://keybase.io/mubix)                  |
| [@OJ](https://github.com/OJ)                      | [oj](https://keybase.io/oj)                        |
| [@scriptjunkie](https://github.com/scriptjunkie)  | [scriptjunkie](https://keybase.io/scriptjunkie)    |
| [@sgonzalez-r7](https://github.com/sgonzalez-r7)  | [essgee](https://keybase.io/essgee)                |
| [@space-r7](https://github.com/space-r7)          | [shelbyp](https://keybase.io/shelbyp)              |
| [@tdoan-r7](https://github.com/tdoan-r7)          | [doanosaur](https://keybase.io/doanosaur)          |
| [@timwr](https://github.com/timwr)                | [timwr](https://keybase.io/timwr)                  |
| [@todb-r7](https://github.com/todb-r7)            | [todb](https://keybase.io/todb)                    |
| [@void-in](https://github.com/void-in)            | [void_in](https://keybase.io/void_in)              |
| [@wchen-r7](https://github.com/wchen-r7)          | [wchenr7](https://keybase.io/wchenr7)              |
| [@wvu-r7](https://github.com/wvu-r7)              | [wvu](https://keybase.io/wvu)                      |
| [@zeroSteiner](https://github.com/zeroSteiner)    | [zerosteiner](https://keybase.io/zerosteiner)      |

Note, keybase.io does **not require** your private key to prove your GitHub
identity. Actually sharing your private key with Keybase.io is a matter of
contention -- here's the usual argument [against][con-sharing], and here's one
thoughtful argument [for][pro-sharing].

As all Metasploit Framework committers are quite comfortable with the command
line, there should be no need to store your (encrypted) private key with a
third party. So, please don't, unless you have amazingly good reasons (and a great
local password).

# Tracking criteria

In order to get [@bcook-r7](https://github.com/bcook-r7) to track your key, you
alert him to its existence through some non-GitHub means, and verify your
GitHub username. That's all there is to it.

It would be sociable to track him (and everyone else on this list) back.
Tracking is essentially "trusting" and "verifying" -- see the much longer
discussion [here][tracking].

# Signing your commits and merges

Contributors are encouraged to sign commits, while Metasploit committers are required to sign their merge commits.  Note that the name and e-mail address must match the information on the signing key exactly.  To begin:

1. Generate a signing key, if you don't have one already, using your favorite PGP/GPG interface:

```
$ gpg --gen-key
gpg (GnuPG) 1.4.20; Copyright (C) 2015 Free Software Foundation, Inc.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Please select what kind of key you want:
   (1) RSA and RSA (default)
   (2) DSA and Elgamal
   (3) DSA (sign only)
   (4) RSA (sign only)
Your selection? 4
RSA keys may be between 1024 and 4096 bits long.
What keysize do you want? (2048) 
Requested keysize is 2048 bits
Please specify how long the key should be valid.
         0 = key does not expire
      <n>  = key expires in n days
      <n>w = key expires in n weeks
      <n>m = key expires in n months
      <n>y = key expires in n years
Key is valid for? (0) 1y
Key expires at Fri 20 Dec 2019 01:38:11 PM CST
Is this correct? (y/N) y

You need a user ID to identify your key; the software constructs the user ID
from the Real Name, Comment and Email Address in this form:
    "Heinrich Heine (Der Dichter) <heinrichh@duesseldorf.de>"

Real name: Dade Murphy
Email address: dmurphy@thegibson.example
Comment: 
You selected this USER-ID:
    "Dade Murphy <dmurphy@thegibson.example>"

Change (N)ame, (C)omment, (E)mail or (O)kay/(Q)uit? o
You need a Passphrase to protect your secret key.

Enter passphrase: [...]
```

2. Modify your `.git/config` file to enable signing commits and merges by default:

````
[user]
  name = Your Name
  email = your_email@example.com
  signingkey = DEADBEEF # Must match name and email exactly!
[alias]
  c = commit -S --edit
  m = merge -S --no-ff --edit
````

Using `git c` and `git m` from now on will sign every commit with your `DEADBEEF` key. However, note that rebasing or cherry-picking commits will change the commit hash, and therefore, unsign the commit -- to resign the most recent, use `git c --amend`.

[msf-committers]:https://github.com/rapid7/metasploit-framework/wiki/Committer-Rights
[pro-sharing]:https://filippo.io/on-keybase-dot-io-and-encrypted-private-key-sharing/
[con-sharing]:https://www.tbray.org/ongoing/When/201x/2014/03/19/Keybase#p-5
[tracking]:https://github.com/keybase/keybase-issues/issues/100