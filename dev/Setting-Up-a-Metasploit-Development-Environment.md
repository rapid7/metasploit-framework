# Metasploit Development Environment

<sup>*The shortlink to this wiki page is http://r-7.co/MSF-DEV*</sup>

This is a guide for setting up an environment for effectively **contributing
to the Metasploit Framework**. If you just want to use Metasploit for
legal, authorized hacking, we recommend instead you [download the Metasploit
binary installer](http://metasploit.com/download), which will take care of
all the dependencies and give you access to the open source Metasploit
Framework, the free Metasploit Community edition, and an option to start
the free trial for Metasploit Pro.

If you're using Kali Linux, Metasploit is already pre-installed for
non-development purposes; just type `msfconsole` in the terminal to
start Metasploit Framework, then type `go_pro` if you'd like to try
Metasploit Pro or Metasploit Community.

If you want to develop on and [contribute] to Metasploit, read on!
This guide should get you going on pretty much any Debian-based
Linux system, but it is written for Kali Linux in particular,
since many, many Metasploit Users are also Kali Linux users, and
why spin up a different VM?

If you're familiar with Ubuntu or Xandros or any other Debian
distro, you should be able to read along here and get it to
work for you. If there are distro-specific gotchas you spot,
please [let us know][issues]!

If you would like to sometimes develop Metasploit-Framework, and
sometimes just use the Metasploit Community Edition which ships with
Kali, you will want to likely create separate user accounts. You might
be able to get away with different Gnome Terminal profiles, but you're
not running out of UIDs, I promise. At the very least, you're going to
need a non-root account for Metasploit Framework development work.

For this guide, the example user is "YOUR_USERNAME," and the sample
password in this document is "YOUR_PASSWORD." Anywhere you see those
strings, use your own username and password. Obviously, they should
be hard.

Each section will have a **TLDR** code snippet, suitable for
copy-pasting, if you just want to speed through things, then a more
complete explination of what's going on with the TLDR broken down into
more of a step-by-step. Keep in mind that as written, many of these
can overwrite any local customization you might have, may have
less secure defaults than you'd like, and other surprises. Use them
only if you are impatient, have done this all before, and understand the
risks.

At the end of this document, there's a [TLDR of TLDRs](#tldr-of-tldrs).
You can't yet run it all at once and go off to lunch, but setup should
now be only a few lightly edited copy-pastes away. <sup>*TODO: Ansible!*</sup>

So let's get started!

# Update Kali Linux

#### TLDR (as root)

----
```bash
echo deb http://http.kali.org/kali kali main non-free contrib > /etc/apt/sources.list &&
echo deb-src http://http.kali.org/kali kali main non-free contrib >> /etc/apt/sources.list &&
echo deb http://security.kali.org/kali-security kali/updates main contrib non-free >> /etc/apt/sources.list &&
apt-get clean &&
rm -rf /var/lib/apt/lists;
apt-get update &&
apt-get -y --force-yes install kali-archive-keyring &&
apt-get update &&
apt-get -y upgrade
```
----

First, you need to know where all the Linux goodness lives. Your `/etc/apt/sources.list` should have these sources listed:

```
deb http://http.kali.org/kali kali main non-free contrib
deb-src http://http.kali.org/kali kali main non-free contrib
deb http://security.kali.org/kali-security kali/updates main contrib non-free
```

If you're missing any of these, add them. If you have a lot of extras, you are almost certain to cause conflicts. [Don't do that][kali-sources]. Once you're set with sources, clean out any cruft, get the latest Kali signing key, and go to town:


```
apt-get clean
rm -rf /var/lib/apt/lists
apt-get update 
apt-get -y --force-yes install kali-archive-keyring
apt-get update
apt-get -y upgrade
```

# Enable remote access

#### TLDR (as root)

----
```bash
apt-get -y install ufw;
ufw enable &&
ufw allow 4444:4464/tcp &&
ufw allow 8080:8090/tcp &&
ufw allow ssh &&
service ssh start
```
----

Often, you need to have remote access back to your Kali machine;
a typical use case is for reverse shells. You might also want to
use ssh and scp to write code and copy files, from elsewhere --
this is especially useful if you're running Kali as a guest OS
and don't want to install VMWare Tools.

```
apt-get -y install ufw
ufw enable
ufw allow 4444:4464/tcp # For default reverse shells
ufw allow 8080:8090/tcp # For browser exploits
ufw allow ssh && service ssh start # If you want to shell in from elsewhere
```

# Create a Dev User

#### TLDR (as root)

----
```bash
useradd -m msfdev &&
PASS=`tr -dc A-Za-z0-9_ < /dev/urandom | head -c8`;
echo ** RECORD THIS: Your msfdev Kali user password is $PASS ** &&
echo "msfdev:$PASS" | chpasswd &&
unset PASS &&
usermod -a -G sudo msfdev &&
chsh -s /bin/bash msfdev
```
**SWITCH TO THIS NON-ROOT USER NOW.**
----

You will want to create a non-root user. In this example, the user is `msfdev`. Neither Git nor RVM likes you to be root, since weird things can easily happen with your filesystem permissions.

```
useradd -m msfdev
passwd msfdev # Set a decent password, or use a script
usermod -a -G sudo msfdev
chsh -s /bin/bash msfdev
```

Once this is complete, switch to this user by logging out of `root` and logging back in as `msfdev`. While some steps down the line will still require sudoer access, you should resist the temptation to keep being root. You will invariably forget to switch and start getting mystery errors about unable to read critical resources that RVM and Git need.

# Install the base dev packages

#### TLDR (as msfdev)

----
```bash
echo 'YOUR_PASSWORD_FOR_KALI' | sudo -kS apt-get -y install \
  build-essential zlib1g zlib1g-dev \
  libxml2 libxml2-dev libxslt-dev locate \
  libreadline6-dev libcurl4-openssl-dev git-core \
  libssl-dev libyaml-dev openssl autoconf libtool \
  ncurses-dev bison curl wget xsel postgresql \
  postgresql-contrib libpq-dev \
  libapr1 libaprutil1 libsvn1 \
  libpcap-dev libsqlite3-dev
```
----

The TLDR here is all you should need to stage up Kali (or any other
Debian-based distro) for a proper dev environment. Note, there's no Ruby
or editor -- we'll get to those next.

# Install RVM

#### TLDR (as msfdev)

----
```bash
curl -sSL https://rvm.io/mpapis.asc | gpg --import - &&
curl -L https://get.rvm.io | bash -s stable --autolibs=enabled --ruby=2.1.6 &&
source $HOME/.rvm/scripts/rvm &&
gem install bundler &&
ruby -v && # See that it's 2.1.6
sudo gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.defaults \
  --type boolean --set /apps/gnome-terminal/profiles/Default/login_shell true
```
----

Kali, like most operating system distributions, does not ship with the
latest Ruby with any predictable frequency. So, we'll use RVM, the Ruby
Version Manager. You can read up on it here: https://rvm.io/, and
discover it's pretty swell. Some people prefer rbenv, and those
instructions [are here][rbenv]. For our purposes, though, we're going to
stick to RVM.

First, you need the signing key for the RVM distribution:

```
curl -sSL https://rvm.io/mpapis.asc | gpg --import -
```

Next, get RVM itself:

```
curl -L https://get.rvm.io | bash -s stable --autolibs=enabled --ruby=2.1.6
```

This does pipe straight to bash, which can be a [sensitive
issue][dont-pipe]. For the longer, safer way:

```
curl - rvm.sh -L https://get.rvm.io
cat rvm.sh # Read it and see it's all good
cat rvm.sh | bash -s stable --autolibs=enabled --ruby=2.1.6
```

Once that's done, fix your current terminal to use RVM's version of ruby:

```
source $HOME/.rvm/scripts/rvm
ruby -v # See that it's 2.1.6
```

And finally, install the `bundler` gem in order to get all the other gems you'll need:

```
gem install bundler
```

## Configure Gnome Terminal to use RVM

To always use RVM's version of ruby in Gnome Terminal, run the
following:

```
sudo gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.defaults \
 --type boolean --set /apps/gnome-terminal/profiles/Default/login_shell true
```

Or, you can navigate to Edit > Profiles >
Highlight Default > Edit > Title and Command > Check **[ ] Run command
as a login shell**. It looks like this:

[[/screens/kali-gnome-terminal.png]]

Finally, see that you're now running Ruby 2.1.6:

```
ruby -v
```

It should say `ruby 2.1.6p336`, unless there is a later version and this doc hasn't been updated yet.

# Install an Editor

#### TLDR (as msfdev)

----
```
sudo apt-get install vim-gnome -y &&
curl -Lo- https://bit.ly/janus-bootstrap | bash
```
----

I like gvim, and many others do, too. I also like
[Janus](https://github.com/carlhuda/janus), a collection of plugins that
supports a bunch of different languages, including Ruby. The TLDR above
will install both of these. Again, if you don't like piping curl output
straight to bash, do it your saner, slower way.

Many choices of editor exist, of course. An informal straw poll shows
that many Metasploit developers use
[Rubymine](https://www.jetbrains.com/ruby/), a few use
[emacs](http://i.imgur.com/dljEqtL.gif), and still others use [Sublime
Text](http://www.sublimetext.com/) with some helpful
[plugins](https://gist.github.com/kernelsmith/5308291).

For this setup, though, let's just say you're a vim person, and move on.

# Generate an SSH Key

#### TLDR (as msfdev)

----
```bash
mkdir -p $HOME/.ssh &&
cat <<EOF>> $HOME/.ssh/config

Host github
  Hostname github.com
  User git
  StrictHostKeyChecking no
  PreferredAuthentications publickey
  IdentityFile ~/.ssh/id_rsa.github

EOF

PASS=`tr -dc A-Za-z0-9_ < /dev/urandom | head -c8` &&
echo ** RECORD THIS: Your SSH key password is $PASS ** &&
ssh-keygen -t rsa -C "YOUR_USERNAME_FOR_EMAIL" -f $HOME/.ssh/id_rsa.github -N $PASS &&
eval "$(ssh-agent -s)" &&
ssh-add $HOME/.ssh/id_rsa.github &&
PUBKEY_GIT=`cat $HOME/.ssh/id_rsa.github.pub` &&
curl -u "YOUR_USERNAME_FOR_GITHUB:YOUR_PASSWORD_FOR_GITHUB" \
  --data "{\"title\":\"msfdev-key\",\"key\":\"$PUBKEY_GIT\"}" \
  https://api.github.com/user/keys &&
history -c &&
unset PUBKEY_GIT &&
unset PASS &&
ssh -T github
```
----

The easiest way we've found to interact with GitHub is over
SSH, using a custom SSH key. This saves us the trouble of
typing passwords over HTTPS connections all the time. So,
read the [generating-ssh-keys] article on GitHub and follow
those instructions, or just perform the steps in the TLDR,
above.

Note, the above will save your GitHub password in your local
history file, so you might want to modify the `curl -u` to
just your username and get prompted for it. Also, you'll want
to set decent passwords for your GitHub account and your local
SSH key.

<blockquote>
Note, if you already have two-factor authentication (aka, 2FA)
enabled, you will get a JSON-formatted error message of "Must
specify two-factor authentication OTP code." In that case,
you'll want to just navigate to
https://github.com/settings/ssh and add your key manually via
the web interface.
</blockquote>

## Create an .ssh/config entry for Github

Once you have your new SSH key all set up, add this to your
$HOME/.ssh/config -- create that file if you don't have one
already.

```
Host github
  Hostname github.com
  User git
  StrictHostKeyChecking no
  PreferredAuthentications publickey
  IdentityFile ~/.ssh/id_rsa.github
```

Test it:

```
ssh -T git@github.com
Warning: Permanently added 'github.com,192.30.252.130' (RSA) to the list of known hosts.
Hi YOUR_USERNAME_FOR_GITHUB! You've successfully authenticated, but GitHub does not provide shell access.
```

Okay! You're all set to fork and clone Metasploit Framework.
How exciting for you!

# Fork and Clone Metasploit-Framework

#### TLDR (as msfdev)

----
```bash
curl -X POST -u "YOUR_USERNAME_FOR_GITHUB:YOUR_PASSWORD_FOR_GITHUB" \
  https://api.github.com/repos/rapid7/metasploit-framework/forks &&
history -c &&
mkdir -p $HOME/git &&
cd $HOME/git &&
sleep 300 &&
git clone github:YOUR_USERNAME_FOR_GITHUB/metasploit-framework &&
cd metasploit-framework
```
----

The TLDR is nice in that it's all command-line. However, you
can do all this just as easily in the web UI (and again, if
you have 2FA enabled, you must use the web UI). Just follow
the [forking] instructions provided by GitHub.

## Clone

One you have a fork on GitHub, it's time to pull it down to your
local dev machine. Again, you'll want to follow the [cloning]
instructions at GitHub, except instead of using
`https://github.com/username/repo`, you'll be using your ssh
alias, `github:username/repo`, like so:

```
mkdir -p $HOME/git
cd $HOME/git
git clone github:YOUR_USERNAME_FOR_GITHUB/metasploit-framework
cd metasploit-framework
```

# Install Bundled Gems

#### TLDR (as msfdev)

----
```bash
cd $HOME/git/metasploit-framework &&
(BUNDLEJOBS=$(expr $(cat /proc/cpuinfo | grep vendor_id | wc -l) - 1) &&
bundle config --global jobs $BUNDLEJOBS) &&
bundle install &&
./msfconsole -x exit
```
----

Metasploit has loads of gems (Ruby libraries) that it depends
on. Because you're using RVM, though, you can install them
locally and not worry about conflicting with Debian-packaged
gems, thanks to the magic of [Bundler]. First, you want to set
bundler up to take advantage of your available cores -- ideally,
your number of CPUs minus one. That can be accomplished by:

```
(BUNDLEJOBS=$(expr $(cat /proc/cpuinfo | grep vendor_id | wc -l) - 1) &&
bundle config --global jobs $BUNDLEJOBS)
```

Next, just navigate to the top-level of your local checkout, and run:

```
cd $HOME/git/metasploit-framework/
bundle install
```

After a minute or two, you're all set to start Metasploiting. In
your checkout directory, type:

```
./msfconsole
```

And bask in the glory that is a functioning source checkout -- and
incidentally create your `~/.msf4` directory upon first start.

```
msfdev@lys:~/git/metasploit-framework$ ./msfconsole
[*] Starting the Metasploit Framework console.../

                 _---------.
             .' #######   ;."
  .---,.    ;@             @@`;   .---,..
." @@@@@'.,'@@            @@@@@',.'@@@@ ".
'-.@@@@@@@@@@@@@          @@@@@@@@@@@@@ @;
   `.@@@@@@@@@@@@        @@@@@@@@@@@@@@ .'
     "--'.@@@  -.@        @ ,'-   .'--"
          ".@' ; @       @ `.  ;'
            |@@@@ @@@     @    .
             ' @@@ @@   @@    ,
              `.@@@@    @@   .
                ',@@     @   ;           _____________
                 (   3 C    )     /|___ / Metasploit! \
                 ;@'. __*__,."    \|--- \_____________/
                  '(.,...."/


       =[ metasploit v4.11.0-dev [core:4.11.0.pre.dev api:1.0.0]]
+ -- --=[ 1420 exploits - 802 auxiliary - 229 post        ]
+ -- --=[ 358 payloads - 37 encoders - 8 nops             ]
+ -- --=[ Free Metasploit Pro trial: http://r-7.co/trymsp ]

msf > ls ~/.msf4
[*] exec: ls ~/.msf4

history
local
logos
logs
loot
modules
plugins
msf > exit
```

Alas, though, you have no database set up to use all this
hacking madness. Easily solved, though!

# Set up PostgreSQL

Kali linux already ships with Postgresql, so we can use that
out of the gate. Everything should just work on Ubuntu and
other Debian-based distros, assuming they have an equivalent
`postgresql` package. The TLDR ensures that the database is
starts up on system start, as well.

## Start the database

#### TLDR (as msfdev)

----
```
echo 'YOUR_PASSWORD_FOR_KALI' | sudo -kS update-rc.d postgresql enable &&
echo 'YOUR_PASSWORD_FOR_KALI' | sudo -S service postgresql start &&
cat <<EOF> $HOME/pg-utf8.sql
update pg_database set datallowconn = TRUE where datname = 'template0';
\c template0
update pg_database set datistemplate = FALSE where datname = 'template1';
drop database template1;
create database template1 with template = template0 encoding = 'UTF8';
update pg_database set datistemplate = TRUE where datname = 'template1';
\c template1
update pg_database set datallowconn = FALSE where datname = 'template0';
\q
EOF
sudo -u postgres psql -f $HOME/pg-utf8.sql &&
sudo -u postgres createuser msfdev -dRS &&
sudo -u postgres psql -c \
  "ALTER USER msfdev with ENCRYPTED PASSWORD 'YOUR_PASSWORD_FOR_PGSQL';" &&
sudo -u postgres createdb --owner msfdev msf_dev_db &&
sudo -u postgres createdb --owner msfdev msf_test_db &&
cat <<EOF> $HOME/.msf4/database.yml
# Development Database
development: &pgsql
  adapter: postgresql
  database: msf_dev_db
  username: msfdev
  password: YOUR_PASSWORD_FOR_PGSQL
  host: localhost
  port: 5432
  pool: 5
  timeout: 5

# Production database -- same as dev
production: &production
  <<: *pgsql

# Test database -- not the same, since it gets dropped all the time
test:
  <<: *pgsql
  database: msf_test_db
EOF
```
----

On Kali Linux, postgresql (and any other listening service)
isn't enabled by default. This is a fine security and
resource precaution, but if you're expecting it there all the
time, feel free to auto-start it:

```
update-rc.d postgresql enable
```

Next, switch to the postgres user to perform a little database
maintenance to fix the default encoding (helpfully provided in
[@ffmike's gist][ffmike-gist]).

```
sudo -sE su postgres
psql
update pg_database set datallowconn = TRUE where datname = 'template0';
\c template0
update pg_database set datistemplate = FALSE where datname = 'template1';
drop database template1;
create database template1 with template = template0 encoding = 'UTF8';
update pg_database set datistemplate = TRUE where datname = 'template1';
\c template1
update pg_database set datallowconn = FALSE where datname = 'template0';
\q
```

## Create the database user 'msfdev'

While still as the postgres user:

```
createuser msfdev -dPRS              # Come up with another great password
createdb --owner msfdev msf_dev_db   # Create the development database
createdb --owner msfdev msf_test_db  # Create the test database
exit                                 # Become msfdev again
```

## Create the database.yml

Now that yourself again, create a file `$HOME/.msf4/database.yml`
with the following:

```yaml
# Development Database
development: &pgsql
  adapter: postgresql
  database: msf_dev_db
  username: msfdev
  password: YOUR_PASSWORD_FOR_PGSQL
  host: localhost
  port: 5432
  pool: 5
  timeout: 5

# Production database -- same as dev
production: &production
  <<: *pgsql

# Test database -- not the same, since it gets dropped all the time
test:
  <<: *pgsql
  database: msf_test_db
```

The next time you start `./msfconsole`, the development database
will be created. Check with:

```
./msfconsole -qx "db_status; exit"
```

# Run Specs

We use [rspec](http://betterspecs.org/) for most Framework testing.
Make sure it works for you:

```
rake spec
```

You should see over 9000 tests run, mostly resulting in green dots,
a few in yellow stars, and no red errors.

# Configure Git

#### TLDR (as msfdev)

----
```bash
cd $HOME/git/metasploit-framework &&
git remote add upstream github:rapid7/metasploit-framework.git &&
git fetch upstream &&
git checkout -b upstream-master --track upstream/master &&
ruby tools/dev/add_pr_fetch.rb &&
ln -sf ../../tools/dev/pre-commit-hook.rb .git/hooks/pre-commit &&
ln -sf ../../tools/dev/pre-commit-hook.rb .git/hooks/post-merge &&
git config --global user.name   "YOUR_USERNAME_FOR_REAL_LIFE" &&
git config --global user.email  "YOUR_USERNAME_FOR_EMAIL" &&
git config --global github.user "YOUR_USERNAME_FOR_GITHUB" &&
```
----

## Set upstream

First off, if you ever plan to update your local clone with the latest
from upstream, you're going to want to track it. In your
`metasploit-framework` checkout, run the below:

```
git remote add upstream github:rapid7/metasploit-framework.git
git fetch upstream
git checkout upstream-master --track upstream/master
```

Now, you have a branch that points to upstream (the `rapid7` fork)
that's different from your own fork (the original `master` branch that
points to `origin/master`). You might find having `upstream-master` and
`master` being different branches handy (especially if you are a
[Metasploit committer][metasploit-committer], since this makes it less
likely to accidentally push to `rapid7/master`).

<blockquote>
Note: Kali ships with git 1.7.10, so you might consider updating to
something more recent, as there are a few missing features between then
and now. Doing so involves adding a Debian ppa, though, which is frowned
upon in Kali.
</blockquote>

Also note, to speed things up on your initial fetches, you might
consider using `git fetch --depth=10` or so, espeically if you don't
plan on tracking older pull requests individually. If this last sentence
made no sense to you, go ahead and use the `--depth` option. You're not
missing anything important.

## Set up a pull ref

If you'd like to get easy access to upstream pull requests on your
command line -- and who wouldn't -- you need to add the appropriate
fetch reference to your `.git/config`. This is done easily with the
following:

```
tools/dev/add_pr_fetch.rb
```

This will add the appropriate ref for all your remotes, including yours.
Now, you can do fancy things like:

```
git checkout fixes-to-pr-1234 upstream/pr/1234
git push origin
```

The less easy way to do this is described at [GitHub][gh-pr-refs].

All this lets you check out someone else's pull request (PR), make
changes, and publish to your own branch on your own fork. This will, in
turn, allow you to help out on other people's PRs with fixes or
additions.

## Keep in sync

You pretty much **never** want to commit to master directly. Always make
changes in a branch, and then merge those changes. This makes it easy to
keep in sync with upstream and never lose any local changes.

### Sync to upstream/master

Couldn't be easier.

```
git checkout master
git fetch upstream
git rebase --preserve-merges upstream/master
git push origin
```

Do the same for `upstream-master`, if you have one of those branches as
well. This also will work for keeping pull requests in sync with master,
but unless you're running into merge conflicts, you shouldn't need to do
this often.  When you do end up resolving merge conflicts, you'll want
to use `--force` when pushing the re-synced branch, since your commit
history will be different after the rebase.

<blockquote>
Force pushing is **never** okay for rapid7/master, but for in-progress
branches, lying a little about the history isn't a federal crime.
</blockquote>

### Msftidy

In order to lint-check any new modules you're writing, you'll want a
pre-commit and a post-merge hook to run our lint-checker, `msftidy.rb`.
So, symlink like so:

```
cd $HOME/git/metasploit-framework
ln -sf ../../tools/dev/pre-commit-hook.rb .git/hooks/pre-commit
ln -sf ../../tools/dev/pre-commit-hook.rb .git/hooks/post-merge
```


### Naming yourself

Finally, if you ever want to contribute to Metasploit, you need to
configure at least your username and e-mail address, like so:

```
git config user.name   "YOUR_USERNAME_FOR_REAL_LIFE"
git config user.email  "YOUR_USERNAME_FOR_EMAIL"
git config github.user "YOUR_USERNAME_FOR_GITHUB"
```

If you want this to be your default identity for any other git repo you use,
just use the `--global` option to `git config`. Your e-mail address must
match your GitHub-registered e-mail.

### Signing commits

We love signing commits, mainly because we're [terrified of the
alternative][git-horror]. The procedure is [detailed
here][signing-howto]. Note that the name and e-mail address must match
the information on the signing key exactly. Contributors are encouraged
to sign commits, while Metasploit committers are required to sign their
merge commits when they [land pull requests][landing-prs].

# Handy Aliases

No development environment setup would be complete without a few handy
aliases to make your life easier.

## Override installed `msfconsole`

As the development user, you might accidentally try to use the installed
Metasploit `msfconsole`. This won't work for a variety of reasons around
how RVM handles different ruby versions and gemsets. So, create this
alias:

```
echo 'alias msfconsole="pushd $HOME/git/metasploit-framework && ./msfconsole && popd"' >> ~/.bash_aliases
```

If you're looking to use both installed and development versions,
different user accounts are the best way to go.

## Prompt with current Ruby/Gemset/Branch

This is super handy to keep track of where you're at. Drop it in your
`~/.bash_aliases`.

```bash
function git-current-branch {
    git branch 2> /dev/null | sed -e '/^[^*]/d' -e 's/* \(.*\)/(\1) /'
}
export PS1="[ruby-\$(~/.rvm/bin/rvm-prompt v p g)]\$(git-current-branch)\n$PS1"
```

## Git aliases

Git has its own way of handling aliases -- either in `$HOME/.gitconfig`
or `repo-name/.git/config` -- seperate from regular shell aliases. Below
are some of the handier ones.



```rc
# An easy, colored oneline log format that shows signed/unsigned status
nicelog = log --pretty=format:'%Cred%h%Creset -%Creset %s %Cgreen(%cr) %C(bold blue)<%aE>%Creset [%G?]'

# Shorthand commands to always sign (-S) and always edit the commit message.
m = merge -S --no-ff --edit
c = commit -S --edit

# Shorthand to always blame (praise) without looking at whitespace changes
b= blame -w

# Spin up a quick temp branch, because git stash is too spooky.
temp = !"git branch -D temp; git checkout -b temp"

# Create a pull request in a web browser from the CLI. Usage: $1 is HISNAME, $2 is HISBRANCH
# Fixes from @kernelsmith, thanks!
pr-url =!"xdg-open https://github.com/$(git config github.user)/$(basename $(git rev-parse --show-toplevel))/pull/new/$1:$2...$(git branch-current) #"
```

# TLDR of TLDRs

If you're very impatient, you can just cut and paste these sequentially,
and you should have a good time. Someday, this will be normalized into a
proper deploy script, but there are a bunch of passwords to deal with
which is always a security adventure. Again, you'll want to sub in your
own username and password details.

## Run these as root

----
```bash
echo deb http://http.kali.org/kali kali main non-free contrib > /etc/apt/sources.list &&
echo deb-src http://http.kali.org/kali kali main non-free contrib >> /etc/apt/sources.list &&
echo deb http://security.kali.org/kali-security kali/updates main contrib non-free >> /etc/apt/sources.list &&
apt-get clean &&
rm -rf /var/lib/apt/lists;
apt-get update &&
apt-get -y --force-yes install kali-archive-keyring &&
apt-get update &&
apt-get -y upgrade
```

----
```bash
apt-get -y install ufw;
ufw enable &&
ufw allow 4444:4464/tcp &&
ufw allow 8080:8090/tcp &&
ufw allow ssh &&
service ssh start
```

----
```bash
useradd -m msfdev &&
PASS=`tr -dc A-Za-z0-9_ < /dev/urandom | head -c8`;
echo ** RECORD THIS: Your msfdev Kali user password is $PASS ** &&
echo "msfdev:$PASS" | chpasswd &&
unset PASS &&
usermod -a -G sudo msfdev &&
chsh -s /bin/bash msfdev
```
----

## Stop here, switch to `msfdev`

----
```bash
echo 'YOUR_PASSWORD_FOR_KALI' | sudo -kS apt-get -y install \
  build-essential zlib1g zlib1g-dev \
  libxml2 libxml2-dev libxslt-dev locate \
  libreadline6-dev libcurl4-openssl-dev git-core \
  libssl-dev libyaml-dev openssl autoconf libtool \
  ncurses-dev bison curl wget xsel postgresql \
  postgresql-contrib libpq-dev \
  libapr1 libaprutil1 libsvn1 \
  libpcap-dev libsqlite3-dev
```

----
```bash
curl -sSL https://rvm.io/mpapis.asc | gpg --import - &&
curl -L https://get.rvm.io | bash -s stable --autolibs=enabled --ruby=2.1.6 &&
source $HOME/.rvm/scripts/rvm &&
gem install bundler &&
ruby -v && # See that it's 2.1.6
sudo gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.defaults \
  --type boolean --set /apps/gnome-terminal/profiles/Default/login_shell true
```

----
```
echo 'YOUR_PASSWORD_FOR_KALI' | sudo -kS apt-get install vim-gnome -y &&
curl -Lo- https://bit.ly/janus-bootstrap | bash
```

----
```bash
mkdir -p $HOME/.ssh &&
cat <<EOF>> $HOME/.ssh/config

Host github
  Hostname github.com
  User git
  StrictHostKeyChecking no
  PreferredAuthentications publickey
  IdentityFile ~/.ssh/id_rsa.github

EOF

PASS=`tr -dc A-Za-z0-9_ < /dev/urandom | head -c8` &&
echo ** RECORD THIS: Your SSH key password is $PASS ** &&
ssh-keygen -t rsa -C "YOUR_USERNAME_FOR_EMAIL" -f $HOME/.ssh/id_rsa.github -N $PASS &&
eval "$(ssh-agent -s)" &&
ssh-add $HOME/.ssh/id_rsa.github &&
PUBKEY_GIT=`cat $HOME/.ssh/id_rsa.github.pub` &&
curl -u "YOUR_USERNAME_FOR_GITHUB:YOUR_PASSWORD_FOR_GITHUB" \
  --data "{\"title\":\"msfdev-key\",\"key\":\"$PUBKEY_GIT\"}" \
  https://api.github.com/user/keys &&
history -c &&
unset PUBKEY_GIT &&
unset PASS &&
ssh -T github
```

----
```bash
curl -X POST -u "YOUR_USERNAME_FOR_GITHUB:YOUR_PASSWORD_FOR_GITHUB" \
  https://api.github.com/repos/rapid7/metasploit-framework/forks &&
history -c &&
mkdir -p $HOME/git &&
cd $HOME/git &&
sleep 300 &&
git clone github:YOUR_USERNAME_FOR_GITHUB/metasploit-framework &&
cd metasploit-framework
```

----
```bash
cd $HOME/git/metasploit-framework &&
(BUNDLEJOBS=$(expr $(cat /proc/cpuinfo | grep vendor_id | wc -l) - 1) &&
bundle config --global jobs $BUNDLEJOBS) &&
bundle install &&
./msfconsole -x exit
```

----
```
echo 'YOUR_PASSWORD_FOR_KALI' | sudo -kS update-rc.d postgresql enable &&
echo 'YOUR_PASSWORD_FOR_KALI' | sudo -S service postgresql start &&
cat <<EOF> $HOME/pg-utf8.sql
update pg_database set datallowconn = TRUE where datname = 'template0';
\c template0
update pg_database set datistemplate = FALSE where datname = 'template1';
drop database template1;
create database template1 with template = template0 encoding = 'UTF8';
update pg_database set datistemplate = TRUE where datname = 'template1';
\c template1
update pg_database set datallowconn = FALSE where datname = 'template0';
\q
EOF
sudo -u postgres psql -f $HOME/pg-utf8.sql &&
sudo -u postgres createuser msfdev -dRS &&
sudo -u postgres psql -c \
  "ALTER USER msfdev with ENCRYPTED PASSWORD 'YOUR_PASSWORD_FOR_PGSQL';" &&
sudo -u postgres createdb --owner msfdev msf_dev_db &&
sudo -u postgres createdb --owner msfdev msf_test_db &&
cat <<EOF> $HOME/.msf4/database.yml
# Development Database
development: &pgsql
  adapter: postgresql
  database: msf_dev_db
  username: msfdev
  password: YOUR_PASSWORD_FOR_PGSQL
  host: localhost
  port: 5432
  pool: 5
  timeout: 5

# Production database -- same as dev
production: &production
  <<: *pgsql

# Test database -- not the same, since it gets dropped all the time
test:
  <<: *pgsql
  database: msf_test_db
EOF
```
----

```bash
cd $HOME/git/metasploit-framework &&
./msfconsole -qx "db_status; exit" &&
rake spec
```
----

```bash
cd $HOME/git/metasploit-framework &&
git remote add upstream github:rapid7/metasploit-framework.git &&
git fetch upstream &&
git checkout -b upstream-master --track upstream/master &&
ruby tools/dev/add_pr_fetch.rb &&
ln -sf ../../tools/dev/pre-commit-hook.rb .git/hooks/pre-commit &&
ln -sf ../../tools/dev/pre-commit-hook.rb .git/hooks/post-merge &&
git config --global user.name  "YOUR_USERNAME_FOR_REAL_LIFE" &&
git config --global user.email "YOUR_USERNAME_FOR_EMAIL"
```
----

That's it! It's still on you to set up your [aliases](#handy-aliases)
and PGP key for [signing commits](#signing-commits) if you ever
care to land pull requests, but other than that, you're good to go.

Again, if there are any errors, omissions, or better ways to do any of
these things, by all means, open an [issue][issues] and we'll see about
updating this HOWTO.

Thanks especially to [@kernelsmith](https://github.com/kernelsmith)
and [@corelanc0d3r](https://github.com/corelanc0d3r) for their
invaluable help and feedback on this dev environment documentation guide.

[contribute]:http://r-7.co/MSF-CONTRIB
[issues]:https://github.com/rapid7/metasploit-framework/issues
[ffmike-gist]: https://gist.github.com/ffmike/877447
[kali-sources]: http://docs.kali.org/general-use/kali-linux-sources-list-repositories
[gitconfig]:https://github.com/todb-r7/junkdrawer/blob/master/dotfiles/git-repos/gitconfig
[dont-pipe]:http://www.seancassidy.me/dont-pipe-to-your-shell.html
[rbenv]:https://github.com/sstephenson/rbenv#installation
[generating-ssh-keys]:https://help.github.com/articles/generating-ssh-keys/
[2fa]:https://help.github.com/articles/about-two-factor-authentication/
[forking]:https://help.github.com/articles/fork-a-repo/
[cloning]:https://help.github.com/articles/fork-a-repo/#step-2-create-a-local-clone-of-your-fork
[Bundler]:http://bundler.io/
[metasploit-committer]:https://github.com/rapid7/metasploit-framework/wiki/Committer-Rights
[git-horror]:http://mikegerwitz.com/papers/git-horror-story
[signing-howto]:https://github.com/rapid7/metasploit-framework/wiki/Committer-Keys#signing-howto
[landing-prs]:https://github.com/rapid7/metasploit-framework/wiki/Landing-Pull-Requests
[todb]:https://github.com/todb-r7
[gh-pr-refs]:https://help.github.com/articles/checking-out-pull-requests-locally/