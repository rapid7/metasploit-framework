This page lists the keys in use by [Metasploit committers][msf-committers] and
can be used to verify merge commits made to https://github.com/rapid7/metasploit-framework.

### Keybase.io identities

Keybase.io is currently in public beta, but we'll go ahead and treat it as
production ready, since it seems like an easy way to verify identities.

If you're a committer on metasploit-framework, and you need an invite, just ask.

| Github Username                                   | Keybase.io Username                                |
| ------------------------------------------------- | -------------------------------------------------- |
| [@acammack-r7](https://github.com/acammack-r7)    | [acammackr7](https://keybase.io/acammackr7)        |
| [@bcook-r7](https://github.com/bcook-r7)          | [busterb](https://keybase.io/busterb)              |
| [@FireFart](https://github.com/FireFart)          | [firefart](https://keybase.io/firefart)            |
| [@gmikeska-r7](https://github.com/gmikeska-r7)    | [gmikeska_r7](https://keybase.io/gmikeska_r7)      |
| [@hdm](https://github.com/hdm)                    | [hdm](https://keybase.io/hdm)                      |
| [@jlee-r7](https://github.com/jlee-r7)            | [egypt](https://keybase.io/egypt)                  |
| [@jhart-r7](https://github.com/jhart-r7)          | [jhart](https://keybase.io/jhart)                  |
| [@lsato-r7](https://github.com/lsato-r7)          | [louissato](https://keybase.io/lsato)              |
| [@Meatballs1](https://github.com/Meatballs1)      | [meatballs](https://keybase.io/meatballs)          |
| [@OJ](https://github.com/OJ)                      | [oj](https://keybase.io/oj)                        |
| [@scriptjunkie](https://github.com/scriptjunkie)  | [scriptjunkie](https://keybase.io/scriptjunkie)    |
| [@sgonzalez-r7](https://github.com/sgonzalez-r7)  | [essgee](https://keybase.io/essgee)                |
| [@timwr](https://github.com/timwr)                | [timwr](https://keybase.io/timwr)                  |
| [@todb-r7](https://github.com/todb-r7)            | [todb](https://keybase.io/todb)                    |
| [@void-in](https://github.com/void-in)            | [void_in](https://keybase.io/void_in)              |
| [@wchen-r7](https://github.com/wchen-r7)          | [wchenr7](https://keybase.io/wchenr7)              |
| [@wwebb-r7](https://github.com/wwebb-r7)          | [iamwilliam](https://keybase.io/iamwilliam)        |
| [@wvu-r7](https://github.com/wvu-r7)              | [wvu](https://keybase.io/wvu)                      |
| [@zeroSteiner](https://github.com/zeroSteiner)    | [zerosteiner](https://keybase.io/zerosteiner)      |
| [@kgray-r7](https://github.com/wvu-r7)            | [noxferatu](https://keybase.io/noxferatu)          |
| [@dmaloney-r7](https://github.com/dmaloney-r7)    | [thelightcosine](https://keybase.io/thelightcosine)|
| [@bpatterson-r7](https://github.com/bpatterson-r7)| [bpatterson](https://keybase.io/bpatterson)        |

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

# Signing HOWTO

Signing merges and commits is easy and fun. Generate a signing key, if you
don't have one already, using your favorite PGP/GPG interface (I use `gpg
--gen-key`). Then add this to your $HOME/.gitconfig:

````
[user]
  name = Your Name
  email = your_email@example.com
  signingkey = DEADBEEF # Must match name and email exactly!
[alias]
  c = commit -S --edit
  m = merge -S --no-ff --edit
````

Using `git c` and `git m` from now on will sign every commit with your
`DEADBEEF` key. However, note that rebasing or cherry-picking commits will
change the commit hash, and therefore, unsign the commit -- to resign the most
recent, use `git c --amend`.

[msf-committers]:https://github.com/rapid7/metasploit-framework/wiki/Committer-Rights
[pro-sharing]:https://filippo.io/on-keybase-dot-io-and-encrypted-private-key-sharing/
[con-sharing]:https://www.tbray.org/ongoing/When/201x/2014/03/19/Keybase#p-5
[tracking]:https://github.com/keybase/keybase-issues/issues/100