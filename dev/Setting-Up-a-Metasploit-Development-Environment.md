# Metasploit Development Environment

We assume that you're on some recent version of Ubuntu Linux. If not, then you're going to be on your own on how to get all your dependencies lined up . If you've successfully set up a development environment on something non-Ubuntu, and you'd like to share, let us know and we'll link to your tutorial from here.

Please note that Backtrack Linux is not very suitable as a development environment, and you will run into missing upstream packages. It's a great place to use Metasploit, but not so great for hacking on it directly.

Throughout this documentation, we'll be using the example user of "Fakey McFakepants," who has the e-mail address of "mcfakepants@packetfu.com" and a login username of "fakey."



<h2 id="apt">Apt-Get Install</h2>

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
  libpcap-dev
````

Note that this does **not** include an appropriate text editor or IDE, nor does it include the Ruby interpreter. We'll get to that in a second.

<h2 id="rvm">Getting Ruby</h2>

Many standard distributions of Ruby are lacking in one regard or another. Lucky for all of us, Wayne Seguin's RVM has become quite excellent at providing several proven Ruby interpreters. Visit [https://rvm.io/](https://rvm.io/) to read up on it or just trust that it'll all work out with a simple:

````bash
\curl -L https://get.rvm.io | bash -s stable --autolibs=enabled --ruby=1.9.3
````

Note the *lack* of sudo; you will nearly always want to install this as a regular user, and not as root.

Sometimes, depending on your particular platform, this incantation may not be reliable. This is nearly identical, but more typing:

````bash
\curl -o rvm.sh -L get.rvm.io && cat rvm.sh | bash -s stable --autolibs=enabled --ruby=1.9.3
````

Also, if you're sketchy about piping a web site directly to bash, you can perform each step individually, without the &&:

````bash
\curl -o rvm.sh -L get.rvm.io 
less rvm.sh
cat rvm.sh | bash -s stable --autolibs=enabled --ruby=1.9.3
````

Next, load the RVM scripts by either opening a new terminal window, or just run: 

````bash
source ~/.rvm/scripts/rvm
````
If you must be root (eg, on BackTrack or Kali), then you will need to explicitly add this (slightly different) line to the end of /root/.bashrc, instead:

````
source /usr/local/rvm/scripts/rvm
````

Next, you will usually need to tick the `Run command as login shell` on the default profile of gnome-terminal (assuming stock Ubuntu), or else you will get the error message that [RVM is not a function](http://stackoverflow.com/questions/9336596/rvm-installation-not-working-rvm-is-not-a-function).

Finally, you want to install a version of Ruby. 1.9.3 is the recommended version.

````
rvm install 1.9.3-p125
````

Assuming all goes as planned, you should end up with something like this in your shell:

[[/screens/rvm02.png]]
*TODO: update this screenshot with the new docs, namely new rvm sequence and versions*

Once that's finished, it would behoove you to set your default ruby and gemset, as described [in this gist](https://gist.github.com/2625441) by [@claudijd](https://github.com/claudijd) . What I use is:

````bash
rvm use --create --default 1.9.3-p125@msf
````

This will set a default gemset to "msf" which you will be populating a little bit later.

<h2 id="editor">Your Editor</h2>

Once that's done, you can set up your preferred editor. Far be it from us to tell you what editor you use -- people get really attached to these things for some reason. An informal straw poll shows that many Metasloit developers use [vim](http://www.vim.org/), some use [Rubymine](https://www.jetbrains.com/ruby/), and a few use [emacs](http://i.imgur.com/dljEqtL.gif). For this document, let's say you're a vim kind of person, since it's free.

First, get vim, your usual way. Vim-gnome is a pretty safe bet.

````bash
sudo apt-get install vim-gnome -y
````

Next, get Janus. Janus is a set of super-useful plugins and conveniences for Vim. You can read up on it here: https://github.com/carlhuda/janus . Or, again, just trust that Things Will Be Fine, and:

````bash
curl -Lo- https://bit.ly/janus-bootstrap | bash
````

This will checkout a version of Janus (using Git) to your ~/.vim directory. Yep, you now have a git repo in one of your more important dot-directories.

Finally, I have a very small set of defaults, here: https://gist.github.com/4658778 . Drop this in your `~/.vimrc.after` file. Note, **Metasploit no longer uses hard tabs**.

*TODO: Add Rubymine docs, add screenshots for this*
*TODO: Could reference the Sublime Text 2 plugin TidyOnExit for anyone using Sublime

<h2 id="github">Using GitHub</h2>

The entire Metasploit code base is hosted here on GitHub. If you have an old Redmine account over at https://dev.metasploit.com, that's not going to provide authentication and identification on GitHub (but we still take bugs over on Redmine).

[[https://help.github.com/assets/help/set-up-git-27bd5975b24e994bc994ec1cf5c82ff9.gif]]

Setting yourself up on GitHub is [well-documented here](https://help.github.com/articles/set-up-git#platform-all), as is [generating an SSH key](https://help.github.com/articles/generating-ssh-keys).

### Alias GitHub in .ssh/config

I hate having to remember usernames for anything anymore, so I've gotten in the habit of creating Host entries for lots of things in my ~/.ssh/config file. You should try it, it's fun, and it can shorten most of your ssh logins to two words.

For the rest of these instructions, I'm going to assume you have something like this in your config file:

````config
Host github
  Hostname github.com
  User git
  PreferredAuthentications publickey
  IdentityFile ~/.ssh/id_rsa.github
````
To check that it works, just `ssh -T github`, and your result should look like this:

[[/screens/ssh10.png]]

<h1 id="git">Working with Git</h2>

The rest of this document will walk through the usual use case of working with Git and GitHub to get a local source checkout, commit something new, and get it submitted to be part of the Metasploit Framework distribution. 

The example here will commit the file _2.txt_ to _test/git/_ , but imagine that we're committing some new module like _ms_12_020_code_exec.rb_ to _modules/exploits/windows/rdp/_.

<h2 id="fork">Forking Metasploit</h2>

Now that you have a GitHub account, it's time to fork the Metasploit Framework. First, go to https://github.com/rapid7/metasploit-framework, and click the Fork button:

[[/screens/fork01.png]]

Hang out for a few seconds, and behold the animated "Hardcore Forking Action":

[[/screens/fork02.png]]

After that's done, switch back over to your terminal, make a sub-directory for your git clones, and use your previously defined .ssh/config alias to clone up a copy of Metasploit. Note that usernames on GitHub are case-sensitive; McFakePants is different from mcfakepants.

````bash
mkdir git
cd git
git clone https://github.com/mcfakepants/metasploit-framework.git
````

You should end up with a complete copy of Metasploit in the metasploit-framework sub-directory:

[[/screens/fork03.png]]

<h3 id="prompt">Setting Your Prompt</h3>

Now might be a good time to decorate your prompt. At the minimum, you will want [something like this](https://gist.github.com/2555109) in your ~/.bash_aliases to let you know on the prompt which branch you're in, if you're in a git repo. I have no idea how else you would be able to track what branch you're in, honestly.

In the end, you'll have a prompt that looks like:

````
(master) fakey@mazikeen:~/git/metasploit-framework$ 
````

where the master bit changes depending on what branch you're in.

<h2 id="bundle"> Bundle install </h2>

The first time you download Metasploit, you will need to get your Ruby gems lined up. It's as simple as `gem install bundle && bundle install` from your metasploit-framework checkout. It'll look like this:

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

From that point on, you'll want to occasionally run `bundle install` whenever the `Gemfile` changes (`msfupdate` does this automatically).

You do *not* want to run `bundle update` by itself, ever, unless you are very serious about updating every Gem in your gemset to some unknown bleeding-edge version.

<h2 id="database">Configure your database</h2>

While it's possible to run Metasploit without a database, it's growing increasingly uncommon to do so. The fine folks over at the Fedora Project Wiki have a snappy guide to get your database configured for the first time, here: https://fedoraproject.org/wiki/Metasploit_Postgres_Setup

Once that's complete, rename your [database.yml.example](https://github.com/rapid7/metasploit-framework/blob/master/config/database.yml.example) file to 'database.yml' and be sure to fill in at least the "development" and "test" sections.

## Start Metasploit

Now that you have a source checkout of Metasploit and you have all your prerequisite components from apt, rvm, and bundler, you should be able to run it straight from your git clone with `./msfconsole -L`:

[[/screens/fork06.png]]

Note that if you need resources that only root has access to, you'll want to run `rvmsudo ./msfconsole -L` instead.

To start off connected to a database, you will want to run something like `./msfconsole -L -y config/database.yml -e development`

[[/screens/database01.png]]

<h2 id="sync">Keeping in sync</h2>

One of the main reasons to use Git and GitHub is this whole idea of branching in order to keep all the code changes straight. In other source control management systems, branching quickly becomes a nightmare, but in Git, branching happens all the time.

You start off with your first branch, "master," which you pretty much never work in. That branch's job is to keep in sync with everyone else. In the case of Metasploit, "everyone else" is `rapid7/metasploit-framework/branches/master`. Let's see how you can keep up with the upstream changes via regular rebasing from upstream's master branch to your master branch.

### Check out the upstream master branch

This is pretty straightforward. From your local branch on the command line, you can:

````bash
git remote add upstream git://github.com/rapid7/metasploit-framework.git
git fetch upstream
git checkout upstream/master
````

This lets you peek in on upstream, after giving a warning about being in the "detatched HEAD" state (don't worry about that now). From here you can do things like read the change log:

````bash
git log --pretty=oneline --name-only -3
````

It should all look like this in your command window:

[[/screens/git02.png]]

It's pretty handy to have this checkout be persistent so you can reference it later. So, type this:

````bash
git checkout -b upstream-master
````

And this will create a new local branch called "upstream-master." Now, switch back to your master branch and fetch anything new from there:

````bash
git checkout master
git fetch
````

And finally, rebase against your local checkout of the upstream master branch:

````bash
git rebase upstream-master
```` 

Rebasing is the easiest way to make sure that your master branch is identical to the upstream master branch. If you have any local changes, those are "rewound," all the remote changes get laid down, and then your changes get reapplied. It should all look like this:

[[/screens/git03.png]]

Of course, you might occasionally run into rebase conflicts, but let's just assume you won't for now. :) Resolving merge conflicts is a little beyond the scope of this document, but the [Git Community Book](http://book.git-scm.com/) should be able to help. In the meantime, we're working up another wiki page to deal specifically with the details of merging, rebasing, and conflict resolution.

> Note that you can skip the checkout to a local branch and simply always `git rebase upstream/master` as well, but you then lose the chance to review the changes in a local branch first -- this can make unwinding merge problems a little harder.

> A note on terminology: In Git, we often refer to "origin" and "master," which can be confusing. "Origin" is a remote repository which contains all of **your** branches. "Master" is a branch of the source code -- usually the first branch, and the branch you don't tend to commit directly to. 

> "Origin" **isn't** Rapid7's repository -- we usually refer to that repo as "Upstream." In other words, "upstream" is just another way of referring to the "rapid7" remote. 

> Got it? "Origin" is your repo up at GitHub, "upstream" is Rapid7's GitHub repo, and "master" is the primary branch of their respective repos.

All right, moving on.

### Syncing changes

Any time you rebase from upstream (like just now), you're likely to bring in new changes because we're committing stuff all the time. This means that when you rebase, your local branch will be ahead of your remote branch. To get your remote fork up to speed:

````bash
git push origin master
````

It should all look something like this:

[[/screens/git04.png]]

Switch back to your browser, refresh, and you should see the new changes reflected in your repo immediately (those GitHub guys are super fast):

[[/screens/git05.png]]

<h2 id="pull">Pull Requests</h2>

Finally, let's get to pull requests. That's why you're reading all this, after all. Thanks to [@corelanc0d3r](https://github.com/corelanc0d3r) for initially writing this all down from a contributor's perspective.

First, create a new branch from your master branch:

````bash
git checkout master
git checkout -b module-ms12-020
````

Write the module, putting it in the proper sub-directory. Once it's all done and tested, add the module to your repo and push it up to origin:

````bash
git add <path to new module>
git commit -m "added MS012-020 RCE for Win2008 R2"
git push origin module-ms12-020
````
**Please make sure your commit messages conform to this guide: http://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html**. TL;DR - First line should be 50 characters or less, then a blank line, then more explanatory text if necessary, with lines no longer than 72 characters.

That command set should look something like this:

[[/screens/pull02.png]]

In your browser, go to your newly created branch, and click Pull Request. 

[[/screens/pull03.png]]

This will automatically reference upstream's master as the branch to land your pull request, and give you an opportunity to talk about how great your module is, what it does, how to test it, etc.

[[/screens/pull04.png]]

Once you click Send Pull Request, you'll be on upstream's pull queue (in this case, mcfakepants has created pull request #356, which is one of 17 open pull requests).

[[/screens/pull05.png]]

Depending on the position of the stars, someone from the Metasploit core development team will review your pull request, and land it, like so:

[[/screens/pull06.png]]

Now, keep in mind that actually [[landing pull requests]] is a little more involved than just taking your commit and applying it directly to the tree. Usually, there are a few changes to be made, sometimes there's some back and forth on the pull request to see if some technique works better, etc. To have the best chance of actually getting your work merged, you would be wise to consult the [[guidelines for accepting modules and enhancements]].

The upshot is, what's committed to Metasploit is rarely exactly what you initially sent, so once the change is committed, you'll want to rebase your checkout against master to pick up all the changes. If you've been developing in a branch (as you should), you shouldn't hit any conflicts with that.

### Cleaning up

Now that everything's committed and you're rebased, if you'd like to clean out your development branches, you can just do the following:

````bash
git branch -D module-ms12-020
git push origin :module-ms12-020
````

Note that Git branches are cheap (nearly free, in terms of disk space), so this shouldn't happen too terribly often.

***

<h2 id="rspec">Rspec Tests</h2>

We are slowly lurching toward a normal testing environment, and will soon be requiring spec tests to validate changes to the framework. To get in the habit now, run the standard set of tests against your local Metasploit branch. First, make sure you have all the gems installed, then run the `rake spec` task.

````
gem install bundler # Only need to do this once
$ bundle install
rake spec # Do this in the top-level Metasploit root
````

For more on rspec (which is the de-facto testing standard for Ruby projects), see http://rspec.info/ . To add tests, drop them someplace sensible in the `spec` directory, and name your tests `whatever_spec.rb`. 

Adding rspec tests with your functional changes significantly increases your chances of getting your pull request landed in a timely manner.

## Thanks and Feedback

First off, thanks to [@corelanc0d3r](https://github.com/corelanc0d3r) for articulating much of this. If you have suggestions for this wiki, please let [@todb-r7](https://github.com/todb-r7) know.

This document should be enough to get your Metasploit development career started, but it doesn't address huge areas of Git source control management. For that, you'll want to look at the [Git Community Book](http://book.git-scm.com/), the many answered questions on [StackOverflow](http://stackoverflow.com/questions/tagged/git), and the [git cheat sheet](http://cheat.errtheblog.com/s/git/).