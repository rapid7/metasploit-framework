# Metasploit Development Environment

<sup>*The shortlink to this wiki page is http://r-7.co/MSF-DEV*</sup>

This is a guide for setting up an environment for effectively **contributing to the Metasploit Framework**. If you just want to use Metasploit for legal, authorized hacking, we recommend instead you either [download the commercial Metasploit binary installer](http://metasploit.com/download), or the [open-source packages](https://github.com/rapid7/metasploit-framework/wiki/Nightly-Installers) which will take care of all the dependencies for you. The commercial installers also include the option for upgrading to Metasploit Pro and are updated semi-weekly, while the open-source installers are updated every night.

If you are using Kali Linux, Metasploit is already pre-installed. [Follow the instructions](http://docs.kali.org/general-use/starting-metasploit-framework-in-kali) provided by Kali on how to use the provided metasploit-framework package and setup a database.

If you want to develop on and [contribute] to Metasploit, read on! This guide should get you going on pretty much any Debian-based Linux system.

So let's get started!

# Assumptions

* You have a Debian-based Linux environment
* You have a user that is not `root`. In this guide, we're using `msfdev`.
* You have a GitHub account, and have associated an [ssh key][ssh-key] with it.

# Install the base dev packages

```bash
sudo apt-get -y install \
  autoconf \
  bison \
  build-essential \
  curl \
  git-core \
  libapr1 \
  libaprutil1 \
  libcurl4-openssl-dev \
  libgmp3-dev \
  libpcap-dev \
  libpq-dev \
  libreadline6-dev \
  libsqlite3-dev \
  libssl-dev \
  libsvn1 \
  libtool \
  libxml2 \
  libxml2-dev \
  libxslt-dev \
  libyaml-dev \
  locate \
  ncurses-dev \
  openssl \
  postgresql \
  postgresql-contrib \
  wget \
  xsel \
  zlib1g \
  zlib1g-dev
```

Note, there's no Ruby yet -- we'll get to that soon.

# Fork and Clone Metasploit-Framework

You can follow the [forking][forking] instructions provided by GitHub,
but it's basically just click the "Fork" button in the top right of the
framework's repo page.

## Clone

Once you have a fork on GitHub, it's time to pull it down to your local
dev machine. Again, you'll want to follow the [cloning][cloning]
instructions at GitHub.

```
mkdir -p $HOME/git
cd $HOME/git
git clone git@github.com:YOUR_USERNAME_FOR_GITHUB/metasploit-framework
cd metasploit-framework
```

## Set upstream

First off, if you ever plan to update your local clone with the latest
from upstream, you're going to want to track it. In your
`metasploit-framework` checkout, run the below:

```
git remote add upstream git@github.com:rapid7/metasploit-framework.git
git fetch upstream
git checkout -b upstream-master --track upstream/master
```

Now, you have a branch that points to upstream (the `rapid7` fork)
that's different from your own fork (the original `master` branch that
points to `origin/master`). You might find having `upstream-master` and
`master` being different branches handy (especially if you are a
[Metasploit committer][metasploit-committer], since this makes it less
likely to accidentally push to `rapid7/master`).


# Install RVM

Most distributions do not ship with the latest Ruby with any predictable
frequency. So we'll use RVM, the Ruby Version Manager. You can read up
on it here: https://rvm.io/, and discover it's pretty swell. Some people
prefer rbenv. You can [get instructions for rbenv][rbenv], but you'll be
on your own to make sure you have a sane Ruby. Most of the committers
use RVM, so for this guide we're going to stick with it.

First, you need the signing key for the RVM distribution:

```
curl -sSL https://rvm.io/mpapis.asc | gpg --import -
```

Next, get RVM itself:

```
curl -L https://get.rvm.io | bash -s stable
```

This does pipe straight to bash, which can be a [sensitive issue][dont-pipe]. For the longer, safer way:

```
curl -o rvm.sh -L https://get.rvm.io
less rvm.sh # Read it and see it's all good
cat rvm.sh | bash -s stable
```

Once that's done, fix your current terminal to use RVM's version of ruby:

```
source ~/.rvm/scripts/rvm
cd ~/git/metasploit-framework
rvm --install $(cat .ruby-version)
```

And finally, install the `bundler` gem in order to get all the other gems you'll need:

```
gem install bundler
```

## Configure Gnome Terminal to use RVM

Gnome Terminal is a jerk and doesn't make your shell a login shell by
default, so RVM won't work there without a config tweak, like so:

Navigate to Edit > Profiles > Highlight Default > Edit > Title and Command > Check **[ ] Run command
as a login shell**. It looks something like this, depending on your specific version of Gnome:

[[/screens/kali-gnome-terminal.png]]

Finally, see that you're now running the Ruby version in [`.ruby-version`](https://github.com/rapid7/metasploit-framework/blob/master/.ruby-version):

```
ruby -v
```

If you're *still* not running the `.ruby-version` defined version of ruby, you probably need to restart your terminal. Make sure you've added rvm to your terminal startup if your initial install of RVM didn't already with something like:

```bash
echo ''[[ -s "$HOME/.rvm/scripts/rvm" ]] && source "$HOME/.rvm/scripts/rvm"' >> .bashrc
```

# Install Bundled Gems

Metasploit has loads of gems (Ruby libraries) that it depends on. Because you're using RVM, though, you can install them
locally and not worry about conflicting with Debian-packaged gems, thanks to the magic of [Bundler].

Just navigate to the top-level of your local checkout, and run:

```
cd ~/git/metasploit-framework/
bundle install
```

After a minute or two, you're all set to start Metasploiting. In your checkout directory, type:

```
./msfconsole
```

And bask in the glory that is a functioning source checkout -- and incidentally create your `~/.msf4` directory upon first start.

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

Alas, though, you have no database set up to use all this hacking madness. Easily solved, though!

# Set up PostgreSQL

Kali linux already ships with Postgresql, so we can use that out of the gate. Everything should just work on Ubuntu and
other Debian-based distros, assuming they have an equivalent `postgresql` package. The TLDR ensures that the database starts up on system start as well.

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

On Kali Linux, postgresql (and any other listening service) isn't enabled by default. This is a fine security and resource precaution, but if you're expecting it there all the time, feel free to auto-start it:

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

Now that you are yourself again, create a file `$HOME/.msf4/database.yml` with the following:

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

The next time you start `./msfconsole`, the development database will be created. Check with:

```
./msfconsole -qx "db_status; exit"
```

# Run Specs

We use [rspec](http://betterspecs.org/) for most Framework testing. Make sure it works for you:

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
git remote add upstream git@github.com:rapid7/metasploit-framework.git &&
git fetch upstream &&
git checkout -b upstream-master --track upstream/master &&
ruby tools/dev/add_pr_fetch.rb &&
ln -sf ../../tools/dev/pre-commit-hook.rb .git/hooks/pre-commit &&
ln -sf ../../tools/dev/pre-commit-hook.rb .git/hooks/post-merge &&
git config --global user.name   "YOUR_USERNAME_FOR_REAL_LIFE" &&
git config --global user.email  "YOUR_USERNAME_FOR_EMAIL" &&
git config --global github.user "YOUR_USERNAME_FOR_GITHUB"
```
----

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
git push origin
```

This also will work for keeping pull requests in sync with master, but
unless you're running into merge conflicts, you shouldn't need to do
this often. When you do end up resolving merge conflicts, you'll want
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
git config --global user.name   "YOUR_USERNAME_FOR_REAL_LIFE"
git config --global user.email  "YOUR_USERNAME_FOR_EMAIL"
git config --global github.user "YOUR_USERNAME_FOR_GITHUB"
```

Your e-mail address must match your GitHub-registered e-mail.

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
[alias]
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

That's it! It's still on you to set up your [aliases](#handy-aliases)
and PGP key for [signing commits](#signing-commits) if you ever care to
land pull requests, but other than that, you're good to go.

Again, if there are any errors, omissions, or better ways to do any of
these things, by all means, open an [issue][issues] and we'll see about
updating this HOWTO.

Thanks especially to [@kernelsmith](https://github.com/kernelsmith) and
[@corelanc0d3r](https://github.com/corelanc0d3r) for their invaluable
help and feedback on this dev environment documentation guide.

[2fa]:https://help.github.com/articles/about-two-factor-authentication/
[Bundler]:http://bundler.io/
[cloning]:https://help.github.com/articles/fork-a-repo/#step-2-create-a-local-clone-of-your-fork
[contribute]:http://r-7.co/MSF-CONTRIB
[dont-pipe]:http://www.seancassidy.me/dont-pipe-to-your-shell.html
[ffmike-gist]: https://gist.github.com/ffmike/877447
[forking]:https://help.github.com/articles/fork-a-repo/
[ssh-key]:https://help.github.com/articles/generating-ssh-keys/
[gh-pr-refs]:https://help.github.com/articles/checking-out-pull-requests-locally/
[gitconfig]:https://github.com/todb-r7/junkdrawer/blob/master/dotfiles/git-repos/gitconfig
[git-horror]:http://mikegerwitz.com/papers/git-horror-story
[issues]:https://github.com/rapid7/metasploit-framework/issues
[kali-sources]: http://docs.kali.org/general-use/kali-linux-sources-list-repositories
[landing-prs]:https://github.com/rapid7/metasploit-framework/wiki/Landing-Pull-Requests
[metasploit-committer]:https://github.com/rapid7/metasploit-framework/wiki/Committer-Rights
[mirrorlist]:http://http.kali.org/README.mirrorlist
[rbenv]:https://github.com/sstephenson/rbenv#installation
[signing-howto]:https://github.com/rapid7/metasploit-framework/wiki/Committer-Keys#signing-howto
[todb]:https://github.com/todb-r7
