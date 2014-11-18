# Metasploit Development Environment TEST WHOOP

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

If you actually want to develop on and contribute to Metasploit, read on!

## Getting Started

We assume that you're on some recent version of Ubuntu Linux. If not,
then you're going to be on your own on how to get all your dependencies
lined up . If you've successfully set up a development environment on
something non-Ubuntu, and you'd like to share, let us know and we'll
link to your tutorial from here.

Please note that Kali Linux (formerly Backtrack Linux) is not very suitable
as a development environment, and you may run into missing upstream
packages. It's a great place to use Metasploit, but not so great for
hacking on it directly.

Throughout this documentation, we'll be using the example user of "Fakey
McFakepants," who has the e-mail address of "mcfakepants@packetfu.com"
and a login username of "fakey."

## Apt-Get Install

The bare minimum for working on Metasploit effectively is:

````bash
sudo apt-get -y install \
  build-essential zlib1g zlib1g-dev \
  libxml2 libxml2-dev libxslt-dev locate \
  libreadline6-dev libcurl4-openssl-dev git-core \
  libssl-dev libyaml-dev openssl autoconf libtool \
  ncurses-dev bison curl wget postgresql \
  postgresql-contrib libpq-dev \
  libapr1 libaprutil1 libsvn1 \
  libpcap-dev libsqlite3-dev
````

Note that this does **not** include an appropriate text editor or IDE,
nor does it include the Ruby interpreter. We'll get to that in a second.

## Getting Ruby

Many standard distributions of Ruby are lacking in one regard or
another. Lucky for all of us, there are several ways to easily install
and maintain ruby versions. ```rvm``` is popular among many Metasploit
developers and recommended, however ```rbenv``` is a good choice too.  So, pick one of the following:

### rvm

Wayne Seguin's RVM has become quite excellent at providing several proven Ruby interpreters. Visit
[https://rvm.io/](https://rvm.io/) to read up on it or just trust that it'll all work out with a simple:

````bash
\curl -L https://get.rvm.io | bash -s stable --autolibs=enabled --ruby=1.9.3
````

Note the *lack* of sudo; you will nearly always want to install this as
a regular user, and not as root.

Sometimes, depending on your particular platform, this incantation may
not be reliable. This is nearly identical, but more typing:

````bash
\curl -o rvm.sh -L get.rvm.io && cat rvm.sh | bash -s stable --autolibs=enabled --ruby=1.9.3
````

Also, if you're sketchy about piping a web site directly to bash (which you should be), you
can perform each step individually, without the &&:

````bash
\curl -o rvm.sh -L get.rvm.io 
less rvm.sh
cat rvm.sh | bash -s stable --autolibs=enabled --ruby=1.9.3
````

Next, load the RVM scripts by either opening a new terminal window, or
just run: 

````bash
source ~/.rvm/scripts/rvm
````

If you must be root (eg, on BackTrack or Kali), then you will need to
explicitly add this (slightly different) line to the end of
/root/.bashrc, instead:

````
source /usr/local/rvm/scripts/rvm
````

Finally, you will usually need to tick the `Run command as login shell`
on the default profile of gnome-terminal (assuming stock Ubuntu), or
else you will get the error message that [RVM is not a
function](http://stackoverflow.com/questions/9336596/rvm-installation-not-working-rvm-is-not-a-function).

Assuming all goes as planned, you should end up with something like this
in your shell:

[[/screens/rvm_install.png]]
[[/screens/rvm_finish.png]]

Because Metasploit now ships with `.ruby-gemset` and `.ruby-version`
files, you do not need to do anything special to ensure your gems get
stashed in the right place. When you cd to your Metasploit framework
checkout, your environment will automatically switch contexts to
`ruby-1.9.3-p551@metasploit-framework`.

### rbenv

Simply follow [this](https://github.com/sstephenson/rbenv#installation)

### Moving to Ruby 2.1.x

As a Metasploit developer, you are encouraged to use the non-default
2.1.5, and you should see some significant performance increases as a result.
Metasploit is currently cross-compatible with 1.9.3 and 2.1.5. 
Until January 6, 2015, both Ruby 1.9.3 and Ruby 2.1.x are supported; after that,
only 2.1.x will be supported, as 1.9.3 will be [completely end of life'd](https://www.ruby-lang.org/en/news/2014/01/10/ruby-1-9-3-will-end-on-2015/).

If you'd like to use another version of ruby, ```rvm``` and ```rbenv``` can help you easily switch:


#### Using 2.1.x with ```rvm```

Just run `rvm --create --versions-conf use rubyversion@metasploit-framework`, replacing `rubyversion` with whatever version of Ruby you like (see [PR #4136](https://github.com/rapid7/metasploit-framework/pull/4136)).

Running the following will cause your checkout to use Ruby 2.1.5 by default:

````
rvm install 2.1.5 &&
rvm --create --versions-conf use 2.1.5@metasploit-framework &&
pushd ..; popd &&
bundle install
````

#### Using 2.1.x with ```rbenv```

Just run:

```
rbenv shell 2.1.5
````

## Your Editor

Once that's done, you can set up your preferred editor. Far be it from
us to tell you what editor you use -- people get really attached to
these things for some reason. An informal straw poll shows that many
Metasloit developers use [vim](http://www.vim.org/), some use
[Rubymine](https://www.jetbrains.com/ruby/), and a few use
[emacs](http://i.imgur.com/dljEqtL.gif) or [Sublime
Text](http://www.sublimetext.com/) 2 (or 3), for which
[here](https://gist.github.com/kernelsmith/5308291) is some helpful
awesomesauce similar to what's below. For this document, let's say
you're a vim kind of person, since it's free.

First, get vim, your usual way. Vim-gnome is a pretty safe bet.

````bash
sudo apt-get install vim-gnome -y
````

Next, get Janus. Janus is a set of super-useful plugins and conveniences
for Vim. You can read up on it here: https://github.com/carlhuda/janus .
Or, again, just trust that Things Will Be Fine, and:

````bash
curl -Lo- https://bit.ly/janus-bootstrap | bash
````

This will checkout a version of Janus (using Git) to your ~/.vim
directory. Yep, you now have a git repo in one of your more important
dot-directories.

Finally, I have a very small set of defaults, here:
https://gist.github.com/4658778 . Drop this in your `~/.vimrc.after`
file. Note, **Metasploit no longer uses hard tabs**.

*TODO: Add Rubymine docs, add screenshots for this*
*TODO: Could reference the Sublime Text 2 plugin TidyOnExit for anyone
 using Sublime

## Using GitHub

[[https://help.github.com/assets/images/site/set-up-git.gif]]

Setting yourself up on GitHub is [well-documented
here](https://help.github.com/articles/set-up-git#platform-all), as is
[generating an SSH
key](https://help.github.com/articles/generating-ssh-keys).

### Alias GitHub in .ssh/config

I hate having to remember usernames for anything anymore, so I've gotten
in the habit of creating Host entries for lots of things in my
~/.ssh/config file. You should try it, it's fun, and it can shorten most
of your ssh logins to two words.

For the rest of these instructions, I'm going to assume you have
something like this in your config file:

````config
Host github
  Hostname github.com
  User git
  PreferredAuthentications publickey
  IdentityFile ~/.ssh/id_rsa.github
````

To check that it works, just `ssh -T github`, and your result should
look like this:

[[/screens/ssh10.png]]

### Git Aliases

Git is super and everything, but sometimes the commands can be too
arcane, verbose, or long. For that, @todb-r7 has shared a pile of git
aliases that he uses, strategically stashed in his [online junk
drawer](https://github.com/todb-r7/junkdrawer/tree/master/dotfiles/git-repos).
These are useful for both regular contributors and members of the
[Metasploit Committers
Team](https://github.com/rapid7/metasploit-framework/wiki/Committer-Rights),
so unless you like a lot of memorization and sore fingers, you might
want to pick and chose from there what makes sense for you and your
workflow.

### Bundler config

Metasploit Framework now uses Bundler extensively to keep versioned gemsets
all nicely aligned. This means that after pulling a fresh version of Metasploit
from GitHub, you likely need to `bundle install` (**not `bundle update`**). To
make that process move slightly quicker, you're encouraged to install gems
[in parallel](http://robots.thoughtbot.com/parallel-gem-installing-using-bundler)
by first running `bundle config --global jobs X` (where X is the number of CPUs
you have available, minus one).

## Working with Git

The rest of this document will walk through the usual use case of
working with Git and GitHub to get a local source checkout, commit
something new, and get it submitted to be part of the Metasploit
Framework distribution. 

The example here will commit the file _2.txt_ to _test/git/_ , but
imagine that we're committing some new module like
_ms_12_020_code_exec.rb_ to _modules/exploits/windows/rdp/_.

## Forking Metasploit

Now that you have a GitHub account, it's time to fork the Metasploit
Framework. First, go to https://github.com/rapid7/metasploit-framework,
and click the Fork button:

[[/screens/fork01.png]]

Hang out for a few seconds, and behold the animated "Hardcore Forking
Action":

[[/screens/fork02.png]]

After that's done, switch back over to your terminal, make a
sub-directory for your git clones, and use your previously defined
.ssh/config alias to clone up a copy of Metasploit. Note that usernames
on GitHub are case-sensitive; McFakePants is different from mcfakepants.

````bash
mkdir git
cd git
git clone https://github.com/mcfakepants/metasploit-framework.git
````

You should end up with a complete copy of Metasploit in the
metasploit-framework sub-directory:

[[/screens/fork03.png]]

### Setting Your Prompt

Now might be a good time to decorate your prompt. At the minimum, you
will want [something like this](https://gist.github.com/2555109) in your
~/.bash_aliases to let you know on the prompt which branch you're in, if
you're in a git repo. I have no idea how else you would be able to track
what branch you're in, honestly.

In the end, you'll have a prompt that looks like:

````
(master) fakey@mazikeen:~/git/metasploit-framework$ 
````

where the master bit changes depending on what branch you're in.

## Bundle Install

The first time you download Metasploit, you will need to get your Ruby
gems lined up. It's as simple as `gem install bundle && bundle install`
from your metasploit-framework checkout. It'll look like this:

````
(master) fakey@mazikeen:~/git/metasploit-framework$ ./msfconsole -L
[*] Metasploit requires the Bundler gem to be installed
    $ gem install bundler
(master) fakey@mazikeen:~/git/metasploit-framework$ gem install bundler
Successfully installed bundler-1.3.5
1 gem installed
Installing ri documentation for bundler-1.3.5...
Installing RDoc documentation for bundler-1.3.5...
(master) todb@mazikeen:~/git/rapid7/metasploit-framework
$ ./msfconsole -L
Could not find rake-10.0.4 in any of the sources
Run `bundle install` to install missing gems.
(master) fakey@mazikeen:~/git/metasploit-framework$ bundle install
Fetching gem metadata from http://rubygems.org/.........
Fetching gem metadata from http://rubygems.org/..
Updating git://github.com/rapid7/metasploit_data_models.git
Installing rake (10.0.4) 
Installing i18n (0.6.1) 
Installing multi_json (1.0.4) 
Installing activesupport (3.2.13) 
Installing builder (3.0.4) 
Installing activemodel (3.2.13) 
Installing arel (3.0.2) 
Installing tzinfo (0.3.37) 
Installing activerecord (3.2.13) 
Installing database_cleaner (0.9.1) 
Installing diff-lcs (1.2.2) 
Installing factory_girl (4.2.0) 
Installing json (1.7.7) 
Installing pg (0.15.0) 
Using metasploit_data_models (0.6.4) from git://github.com/rapid7/metasploit_data_models.git (at 0.6.4) 
Installing msgpack (0.5.4) 
Installing nokogiri (1.5.9) 
Installing pcaprub (0.11.3) 
Installing redcarpet (2.2.2) 
Installing robots (0.10.1) 
Installing rspec-core (2.13.1) 
Installing rspec-expectations (2.13.0) 
Installing rspec-mocks (2.13.0) 
Installing rspec (2.13.0) 
Installing simplecov-html (0.5.3) 
Installing simplecov (0.5.4) 
Installing yard (0.8.5.2) 
Using bundler (1.3.5) 
Your bundle is complete!
Use `bundle show [gemname]` to see where a bundled gem is installed.
(master) fakey@mazikeen:~/git/metasploit-framework$
````

From that point on, you'll want to occasionally run `bundle install`
whenever the `Gemfile` changes (`msfupdate` does this automatically).

You do *not* want to run `bundle update` by itself, ever, unless you are
very serious about updating every Gem in your gemset to some unknown
bleeding-edge version.

## Configure Your Database

While it's possible to run Metasploit without a database, it's growing
increasingly uncommon to do so. The fine folks over at the Fedora
Project Wiki have a snappy guide to get your database configured for the
first time, here:
https://fedoraproject.org/wiki/Metasploit_Postgres_Setup

Once that's complete, rename your
[database.yml.example](https://github.com/rapid7/metasploit-framework/blob/master/config/database.yml.example)
file to 'database.yml' and be sure to fill in at least the "development"
and "test" sections.

## Start Metasploit

Now that you have a source checkout of Metasploit and you have all your
prerequisite components from apt, rvm, and bundler, you should be able
to run it straight from your git clone with `./msfconsole -L`:

[[/screens/fork06.png]]

Note that if you need resources that only root has access to, you'll
want to run `rvmsudo ./msfconsole -L` instead.

To start off connected to a database, you will want to run something
like `./msfconsole -L -y config/database.yml -e development`

[[/screens/database01.png]]

## Keeping In Sync

One of the main reasons to use Git and GitHub is this whole idea of
branching in order to keep all the code changes straight. In other
source control management systems, branching quickly becomes a
nightmare, but in Git, branching happens all the time.

You start off with your first branch, "master," which you pretty much
never work in. That branch's job is to keep in sync with everyone else.
In the case of Metasploit, "everyone else" is
`rapid7/metasploit-framework/branches/master`. Let's see how you can
keep up with the upstream changes via regular rebasing from upstream's
master branch to your master branch.

### Check out the upstream master branch

This is pretty straightforward. From your local branch on the command
line, you can:

````bash
git remote add upstream git://github.com/rapid7/metasploit-framework.git
git fetch upstream
git checkout upstream/master
````

This lets you peek in on upstream, after giving a warning about being in
the "detatched HEAD" state (don't worry about that now). From here you
can do things like read the change log:

````bash
git log --pretty=oneline --name-only -3
````

It should all look like this in your command window:

[[/screens/git02.png]]

It's pretty handy to have this checkout be persistent so you can
reference it later. So, type this:

````bash
git checkout -b upstream-master
````

And this will create a new local branch called "upstream-master." Now,
switch back to your master branch and fetch anything new from there:

````bash
git checkout master
git fetch
````

And finally, rebase against your local checkout of the upstream master
branch:

````bash
git rebase upstream-master
```` 

Rebasing is the easiest way to make sure that your master branch is
identical to the upstream master branch. If you have any local changes,
those are "rewound," all the remote changes get laid down, and then your
changes get reapplied. It should all look like this:

[[/screens/git03.png]]

Of course, you might occasionally run into rebase conflicts, but let's
just assume you won't for now. :) Resolving merge conflicts is a little
beyond the scope of this document, but the [Git Community
Book](http://book.git-scm.com/) should be able to help. In the meantime,
we're working up another wiki page to deal specifically with the details
of merging, rebasing, and conflict resolution.

> Note that you can skip the checkout to a local branch and simply
always `git rebase upstream/master` as well, but you then lose the
chance to review the changes in a local branch first -- this can make
unwinding merge problems a little harder.

> A note on terminology: In Git, we often refer to "origin" and
"master," which can be confusing. "Origin" is a remote repository which
contains all of **your** branches. "Master" is a branch of the source
code -- usually the first branch, and the branch you don't tend to
commit directly to. 

> "Origin" **isn't** Rapid7's repository -- we usually refer to that
repo as "Upstream." In other words, "upstream" is just another way of
referring to the "rapid7" remote. 

> Got it? "Origin" is your repo up at GitHub, "upstream" is Rapid7's
GitHub repo, and "master" is the primary branch of their respective
repos.

All right, moving on.

### Syncing changes

Any time you rebase from upstream (like just now), you're likely to
bring in new changes because we're committing stuff all the time. This
means that when you rebase, your local branch will be ahead of your
remote branch. To get your remote fork up to speed:

````bash
git push origin master
````

It should all look something like this:

[[/screens/git04.png]]

Switch back to your browser, refresh, and you should see the new changes
reflected in your repo immediately (those GitHub guys are super fast):

[[/screens/git05.png]]

## Pull Requests

Finally, let's get to pull requests. That's why you're reading all this,
after all. Thanks to [@corelanc0d3r](https://github.com/corelanc0d3r)
for initially writing this all down from a contributor's perspective.

First, create a new branch from your master branch:

````bash
git checkout master
git checkout -b module-ms12-020
````

Write the module, putting it in the proper sub-directory. Once it's all
done and tested, add the module to your repo and push it up to origin:

````bash
git add <path to new module>
git commit -m "Add MS012-020 RCE for Win2008 R2"
git push origin module-ms12-020
````

**Please make sure your commit messages conform to this guide:
 http://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html**.
TL;DR - First line should be 50 characters or less, then a blank line,
then more explanatory text if necessary, with lines no longer than 72
characters.

That command set should look something like this:

[[/screens/pull02.png]]

In your browser, go to your newly created branch, and click Pull
Request. 

[[/screens/pull03.png]]

This will automatically reference upstream's master as the branch to
land your pull request, and give you an opportunity to talk about how
great your module is, what it does, how to test it, etc.

[[/screens/pull04.png]]

Once you click Send Pull Request, you'll be on upstream's pull queue (in
this case, mcfakepants has created pull request #356, which is one of 17
open pull requests).

[[/screens/pull05.png]]

Depending on the position of the stars, someone from the Metasploit core
development team will review your pull request, and land it, like so:

[[/screens/pull06.png]]

Now, keep in mind that actually [[landing pull requests]] is a little
more involved than just taking your commit and applying it directly to
the tree. Usually, there are a few changes to be made, sometimes there's
some back and forth on the pull request to see if some technique works
better, etc. To have the best chance of actually getting your work
merged, you would be wise to consult the [[guidelines for accepting
modules and enhancements]].

The upshot is, what's committed to Metasploit is rarely exactly what you
initially sent, so once the change is committed, you'll want to rebase
your checkout against master to pick up all the changes. If you've been
developing in a branch (as you should), you shouldn't hit any conflicts
with that.

### Cleaning up

Now that everything's committed and you're rebased, if you'd like to
clean out your development branches, you can just do the following:

````bash
git branch -D module-ms12-020
git push origin :module-ms12-020
````

Note that Git branches are cheap (nearly free, in terms of disk space),
so this shouldn't happen too terribly often.

***

## Git Hooks

If you plan to work on Metasploit, you should have the standard
pre-commit and post-merge symlinks set up. This is really easy; assuming
you're in the top-level directory of a Metasploit framework checkout,
just type:

````bash
ln -sf ../../tools/dev/pre-commit-hook.rb .git/hooks/pre-commit
ln -sf ../../tools/dev/pre-commit-hook.rb .git/hooks/post-merge
````

This will run this now somewhat misleadingly-named `pre-commit-hook.rb`
before every commit you make, and after every merge, to check your
modules. The pre-commit hook will prevent you from checking in modules
that don't pass msftidy.rb inspection, while post-merge will merely ask
you nicely to not merge new brokenness.

To skip the pre-commit test because nobody's the boss of you, just run
your `git commit` command with the `--no-verify` option. Note that
actually submitting broken modules will make them unlikely landing
candidates by the [Metasploit Committer
Team](https://github.com/rapid7/metasploit-framework/wiki/Committer-Rights)
since they all run the same checks before landing.

## RSpec Tests

We are slowly lurching toward a normal testing environment, now require
rspec tests to validate changes to the core workings of the framework.
To get in the habit, run the standard set of tests against your local
Metasploit branch. First, make sure you have all the gems installed,
then run the `rake spec` task.

````
gem install bundler # Only need to do this once
$ bundle install
rake spec # Do this in the top-level Metasploit root
````

For more on rspec (which is the de-facto testing standard for Ruby
projects), see http://rspec.info/ and http://betterspecs.org. To add
tests, drop them someplace sensible in the `spec` directory, and name
your tests `whatever_spec.rb`. 

Adding rspec tests with your functional changes significantly increases
your chances of getting your pull request landed in a timely manner.

## Signed commits

While not required for most committers, the [Metasploit Committer
Team](https://github.com/rapid7/metasploit-framework/wiki/Committer-Rights)
does sign all of their commits, using [this
procedure](https://github.com/rapid7/metasploit-framework/wiki/Committer-Keys#signing-howto).
Trust me, it's delightfully fun, especially since barely anyone actually
signs commits out in GitHub land. If you would like to validate
signatures (and you should!), you'll want to snag that list of Committer
Keys, as well.

## Next Steps

First off, thanks to [@corelanc0d3r](https://github.com/corelanc0d3r)
for articulating much of this. If you have suggestions for this wiki,
please let [@todb-r7](https://github.com/todb-r7) know.

This document should be enough to get your Metasploit development career
started, but it doesn't address huge areas of Git source control
management. For that, you'll want to look at the [Git Community
Book](http://book.git-scm.com/), the many answered questions on
[StackOverflow](http://stackoverflow.com/questions/tagged/git), and the
[git cheat sheet](http://cheat.errtheblog.com/s/git/).

Finally, you will want to initialize your [mind
grapes](http://www.urbandictionary.com/define.php?term=mind%20grapes)
with the
[CONTRIBUTING.md](https://github.com/rapid7/metasploit-framework/blob/master/CONTRIBUTING.md)
document which we all slavishly follow and has more code style and
content details that you should be aware of.

Also, we're serious about that word "career" -- if you'd like to work on
Metasploit full time, just drop todb@metasploit.com a line with your
resume and see if there are any current or upcoming openings.

## Development on OS X

If you are looking for instructions on how to set up a development environment on OS X, please go to the following link:
http://www.darkoperator.com/installing-metasploit-framewor/