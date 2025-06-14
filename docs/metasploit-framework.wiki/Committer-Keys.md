This page lists the keys in use by [[Metasploit committers|committer-rights]] and
can be used to verify merge commits made to <https://github.com/rapid7/metasploit-framework>.

# Keybase.io identities

Keybase.io is used by Metasploit as an easy way to verify identities of committers. If you're a committer on metasploit-framework, and you need an invite, just ask.

| Github Username                                   | Keybase.io Username                                |
| ------------------------------------------------- | -------------------------------------------------- |
| [@adfoster-r7](https://github.com/adfoster-r7)    | [adfosterr7](https://keybase.io/adfosterr7)        |
| [@bcoles](https://github.com/bcoles)              | [bcoles](https://keybase.io/bcoles)                |
| [@bwatters-r7](https://github.com/bwatters-r7)    | [bwatters](https://keybase.io/bwatters)            |
| [@ccondon-r7](https://github.com/ccondon-r7)      | [catc0n](https://keybase.io/catc0n)                |
| [@cdelafuente-r7](https://github.com/cdelafuente-r7)|[cdelafuente](https://keybase.io/cdelafuente)     |
| [@cgranleese-r7](https://github.com/cgranleese-r7)|                                                    |
| [@chiggins](https://github.com/chiggins)          | [chiggins](https://keybase.io/chiggins)            |
| [@dwelch-r7](https://github.com/dwelch-r7)        | [dwelchr7](https://keybase.io/dwelchr7)            |
| [@erran-r7](https://github.com/erran-r7)          | [err7n](https://keybase.io/err7n)                  |
| [@ekelly-rapid7](https://github.com/ekelly-rapid7)|                                                    |
| [@FireFart](https://github.com/FireFart)          | [firefart](https://keybase.io/firefart)            |
| [@Green-m](https://github.com/Green-m)            | [green-m](https://keybase.io/green_m)              |
| [@gwillcox-r7](https://github.com/gwillcox-r7)    | [grantwillcox](https://keybase.io/grantwillcox)    |
| [@h00die](https://github.com/h00die)              | [h00die](https://keybase.io/h00die)                |
| [@hwilson-r7](https://github.com/hwilson-r7)      |                                                    |
| [@jharris-r7](https://github.com/jharris-r7)      |                                                    |
| [@jheysel-r7](https://github.com/jheysel-r7)      |                                                    |
| [@jmartin-r7](https://github.com/jmartin-r7)      | [jmartinr7](https://keybase.io/jmartinr7)          |
| [@Meatballs1](https://github.com/Meatballs1)      | [meatballs](https://keybase.io/meatballs)          |
| [@mkienow-r7](https://github.com/mkienow-r7)      | [inokii](https://keybase.io/inokii)                |
| [@mubix](https://github.com/mubix)                | [mubix](https://keybase.io/mubix)                  |
| [@nhkaraka-r7](https://github.com/nhkaraka-r7)    |                                                    |
| [@OJ](https://github.com/OJ)                      | [oj](https://keybase.io/oj)                        |
| [@rhodgman-r7](https://github.com/rhodgman-r7)    | [rhodgmanr7](https://keybase.io/rhodgmanr7)        |
| [@scriptjunkie](https://github.com/scriptjunkie)  | [scriptjunkie](https://keybase.io/scriptjunkie)    |
| [@sgonzalez-r7](https://github.com/sgonzalez-r7)  | [essgee](https://keybase.io/essgee)                |
| [@smashery](https://github.com/smashery)          | [smashery](https://keybase.io/smashery)            |
| [@smcintyre-r7](https://github.com/smcintyre-r7)  |                                                    |
| [@space-r7](https://github.com/space-r7)          | [shelbyp](https://keybase.io/shelbyp)              |
| [@tas-r7](https://github.com/tas-r7)              |                                                    |
| [@timwr](https://github.com/timwr)                | [timwr](https://keybase.io/timwr)                  |
| [@todb-r7](https://github.com/todb-r7)            | [todb](https://keybase.io/todb)                    |
| [@void-in](https://github.com/void-in)            | [void_in](https://keybase.io/void_in)              |
| [@zgoldman-r7](https://github.com/zgoldman-r7)    |                                                    |

Note, keybase.io does **not require** your private key to prove your GitHub
identity. Actually sharing your private key with Keybase.io is a matter of
contention -- here's the usual argument [against][con-sharing], and here's one
thoughtful argument [for][pro-sharing].

# Tracking criteria

In order to get [@smcintyre-r7](https://github.com/smcintyre-r7) to track your key, you
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

```ini
[user]
  name = Your Name
  email = your_email@example.com
  signingkey = DEADBEEF # Must match name and email exactly!
[alias]
  c = commit -S --edit
  m = merge -S --no-ff --edit
```

Using `git c` and `git m` from now on will sign every commit with your `DEADBEEF` key. However, note that rebasing or cherry-picking commits will change the commit hash, and therefore, unsign the commit -- to resign the most recent, use `git c --amend`.

[pro-sharing]:https://filippo.io/on-keybase-dot-io-and-encrypted-private-key-sharing/
[con-sharing]:https://www.tbray.org/ongoing/When/201x/2014/03/19/Keybase#p-5
[tracking]:https://github.com/keybase/keybase-issues/issues/100
