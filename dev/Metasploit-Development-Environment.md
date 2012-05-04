# Metasploit Development Environment

The Metasploit Framework is a pretty complex hunk of software, at least according to [Ohloh](http://www.ohloh.net/p/metasploit). So, getting started with development can be daunting even for veteran exploit developers. This page attempts to demystify the process of setting up your Metasploit development environment to submitting a "pull request" to get your exploit into the standard distribution.

This documentation assumes you're on some recent version of Ubuntu Linux. If not, then you're going to be on your own on how to get all your dependencies lined up. If you've successfully set up a development environment on something non-Ubuntu, and you'd like to share, let us know and we'll link to your tutorial from here.

Throughout this documentation, we'll be using the example user of "Fakey McFakepants," who has the e-mail address of "mcfakepants@packetfu.com" and a login username of "fakey."



<h2 id="apt">Apt-Get Install</h2>

The bare minimum for working on Metasploit effectively is:

````bash
apt-get -y install \
  build-essential zlib1g zlib1g-dev \
  libxml2 libxml2-dev libxslt-dev locate \
  libreadline6-dev libcurl4-openssl-dev git-core \
  libssl-dev libyaml-dev openssl autoconf libtool \
  ncurses-dev bison curl wget postgresql \
  postgresql-contrib libpq-dev
````

Note that this does **not** include an appropriate text editor or IDE, nor does it include the Ruby interpreter. We'll get to that in a second.

<h2 id="rvm">Getting Ruby</h2>

Most (all?) standard distributions of Ruby are lacking in one regard or another. Lucky for all of us, Wayne Seguin's RVM has been getting steadily more excellent in providing several proven Ruby interpreters. Visit [https://rvm.io/](https://rvm.io/) to read up on it or just trust that it'll all work out with a simple:

````bash
$ curl -L get.rvm.io | bash -s stable
````

Followed by: 

````bash
$ source ~/.rvm/scripts/rvm
````

And finally:

````bash
$ rvm install 1.9.3-p125
````

What this does is fetch RVM, which performs a bunch of shell voodoo, and installs Ruby version 1.9.3 patchlevel 125 (there are lots of other Rubies to choose from, but we like this one the most right now). Assuming all goes as planned, you should end up with something like this in your shell:

[[/screens/rvm02.png]]

<h2 id="editor">Your Editor</h2>

Once that's done, you can set up your preferred editor. Far be it from us to tell you what editor you use -- people get really attached to these things for some reason. After we put together some docs for sensible defaults for a couple of the more popular editors out there, we'll list them here.

<h2 id="github">Using GitHub</h2>

The entire Metasploit code base is hosted here on GitHub. If you have an old Redmine account over at dev.metasploit.com, that's not going to do much for you since the switch-over -- you're going to need a GitHub account. That process is pretty simple.

### Find the Signup button

[[/screens/new01.png]]

### Create a free user account

[[/screens/new02.png]]

### Come up with a decent username and password

[[/screens/new04.png]]

None of this is exactly rocket science.

<h2 id="ssh">SSH for GitHub</h2>

After that's done, you need to set up an SSH key to associate with your new GitHub identity (this step is **not** optional, so good on GitHub for forcing this minimal level of security).

### Create a new key

We recommend you set up a new SSH key pair to associate with GitHub, rather than reuse that same old key you have in 50 other authorized_keys files around the world. Why not just start fresh? It's easy and fun:

````bash
$ ssh-keygen -t rsa -C "mcfakepants@packetfu.com"
````
Just follow the prompts, pick a name for your key pair (I use "id_rsa.github"), set a password, and you should end up with something like:

[[/screens/ssh01.png]]

### Add your key

Next, go to [https://github.com/settings/ssh](https://github.com/settings/ssh) (which can be navigated to via _Account Settings > SSH Keys_), and click "Add SSH key":

[[/screens/ssh02.png]]

You'll be presented with a screen to copy-paste your public SSH key (not the private one!). The easiest thing to do is to cat your newly created key, select, and copy-paste it:

[[/screens/ssh03.png]]

[[/screens/ssh04.png]]

### Confirm your key

After that's done, you'll have a key associated, and you'll get e-mail about it. Eyeball the fingerprint and make sure it matches up. 

[[/screens/ssh05.png]]

The real moment of truth is when you test your SSH key. If you named it something funny like I did, don't forget the -i flag, use -T to avoid allocating a terminal (you won't get one anyway). Also note that you are going to literally use "git@github.com" as the username (not your name or anything like that).

````bash
$ ssh -i ~/.ssh/id_rsa.github -T git@github.com
````
Your console should look like this:

[[/screens/ssh07.png]]

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

### Minimal Git config

Finally, you're ready to set up your local git config file, if you haven't already:

````bash
git config --global user.name "Fakey McFakepants"
git config --global user.email "mcfakepants@packetfu.com"
````

Cat your ~/.gitconfig to ensure you have that set (and remember, your e-mail address needs to match the address you set back when you ssh-keygen'ed):

[[/screens/ssh11.png]]

<h1 id="git">Working with Git</h2>

The rest of this document will walk through the usual use case of working with Git and GitHub to get a local source checkout, commit something new, and get it submitted to be part of the Metasploit Framework distribution. 

The example here will commit the file _2.txt_ to _test/git/_ , but imagine that we're committing some new module like _ms_12_020_code_exec.rb_ to _modules/exploits/windows/rdp/_.

<h2 id="fork">Forking Metasploit</h2>

Now that you have a GitHub account, it's time to fork the Metasploit Framework. First, go to https://github.com/rapid7/metasploit-framework, and click the Fork button:

[[/screens/fork01.png]]

Hang out for a few seconds, and behold the animated "Hardcore Forking Action":

[[/screens/fork02.png]]

After that's done, switch back over to your terminal, make a sub-directory for your git clones, and use your previously defined .ssh/config alias to clone up a copy of Metasploit:

````bash
$ mkdir git
$ cd git
$ git clone git@github.com:mcfakepants/metasploit-framework.git
````
You should end up with a complete copy of Metasploit in the metasploit-framework sub-directory:

[[/screens/fork03.png]]

<h3 id="prompt">Set Your Prompt</h3>

Now might be a good time to decorate your prompt. I've hacked [this gist](https://gist.github.com/2555109) together for my ~/.bash_aliases. It's a little ugly, but it works.

[[/screens/fork04.png]]

This lets me know on the command line prompt the version of Ruby, the gemset, and the Git branch I happen to be in. The end result looks like this:

[[/screens/fork05.png]]

## Start Metasploit

Now that you have a source checkout of Metasploit, and you have all your prerequisite components from apt and rvm, you should be able to run it straight from your git clone with `./msfconsole -L`:

[[/screens/fork06.png]]

<h2 id="sync">Keeping in sync</h2>

One of the main reasons to use Git and GitHub is this whole idea of branching in order to keep all the code changes straight. In other source control management systems, branching quickly becomes a nightmare, but in Git, branching happens all the time.

You start off with your first branch, "master," which you pretty much never work in. That branch's job is to keep in sync with everyone else. In the case of Metasploit, "everyone else" is `rapid7/metasploit-framework/branches/master`. Let's see how you can keep up with the upstream changes via regular rebasing from upstream's master branch to your master branch.

### Check out the upstream master branch

This is pretty straightforward. From your local branch on the command line, you can:

````bash
$ git remote add upstream git://github.com/rapid7/metasploit-framework.git
$ git checkout upstream/master
````

This lets you peek in on upstream, after giving a warning about being in the "detatched HEAD" state (don't worry about that now). From here you can do things like read the change log:

````bash
$ git log --pretty=oneline --name-only -3
````

It should all look like this in your command window:

[[/screens/git02.png]]

It's pretty handy to have this checkout be persistent so you can reference it later. So, type this:

````bash
$ git checkout -b upstream-master
````

And this will create a new branch called "upstream-master." Now, switch back to your master branch and fetch anything new from there:

````bash
$ git checkout master
$ git fetch
````

And finally, rebase against the upstream. 

Rebasing is the easiest way to make sure that your master branch is identical to the upstream master branch. If you have any local changes, those are "rewound," all the remote changes get laid down, and then your changes get reapplied. It should all look like this:

[[/screens/git03.png]]

Of course, you might occasionally run into rebase conflicts, but let's just assume you won't for now. :) Resolving merge conflicts is a little beyond the scope of this document, but the [Git Community Book](http://book.git-scm.com/) should be able to help.

> A note on terminology: In Git, we often refer to "origin" and "master," which can be confusing. "Origin" is a remote repository which contains all of **your** branches. "Master" is a branch of the source code -- usually the first branch, and the branch you don't tend to commit directly to. 

> "Origin" **isn't** Rapid7's repository -- we usually refer to that repo as "Upstream." In other words, "upstream" is just another way of referring to the "rapid7" remote. 

> Got it? "Origin" is your repo up at GitHub, "upstream" is Rapid7's GitHub repo, and "master" is the primary branch of their respective repos.

All right, moving on.

### Syncing changes

Any time you rebase from upstream, you're likely to bring in new changes because we're committing stuff all the time. This means that when you rebase, your local branch will be ahead of your remote branch. To get your remote up to speed:

````bash
$ git push origin master
````

It should all look something like this:

[[/screens/git04.png]]

Switch back to your browser, refresh, and you should see the new changes reflected in your repo immediately (those GitHub guys are super fast):

[[/screens/git05.png]]

<h2 id="pull">Pull Requests</h2>

Finally, let's get to pull requests. That's why you're reading all this, after all. Thanks to [@corelanc0d3r](https://github.com/corelanc0d3r) for initially writing this all down from a contributor's perspective.

First, create a new branch:

````bash
git checkout -b module-ms12-020
````

Write the module, putting it in the proper sub-directory. Once it's all done and tested, add the module to your repo and push it up to origin:

````bash
git add <path to new module>
git commit -m "added MS012-020 RCE for Win2008 R2"
git push origin module-ms12-020
````

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

Now, keep in mind that actually [[landing a pull request]] is a little more involved than just taking your commit and applying it directly to the tree. Usually, there are a few changes to be made, sometimes there's some back and forth on the pull request to see if some technique works better, etc. To have the best chance of actually getting your work merged, you would be wise to consult the [[Acceptance Guidelines]].

The upshot is, what's committed to Metasploit is rarely exactly what you initially sent, so once the change is committed, you'll want to rebase your checkout against master to pick up all the changes. If you've been developing in a branch (as you should), you shouldn't hit any conflicts with that.

### Cleaning up

Now that everything's committed and you're rebased, if you'd like to clean out your development branches, you can just do the following:

````bash
$ git branch -D module-ms12-020
$ git push origin :module-ms12-020
````

Note that Git branches are cheap (nearly free, in terms of disk space), so this shouldn't happen too terribly often.

***

## Thanks and Feedback

First off, thanks to [@corelanc0d3r](https://github.com/corelanc0d3r) for articulating much of this. If you have suggestions for this wiki, please let [@todb-r7](https://github.com/todb-r7) know.

This document should be enough to get your Metasploit development career started, but it doesn't address huge areas of Git source control management. For that, you'll want to look at the [Git Community Book](http://book.git-scm.com/), the many answered questions on [StackOverflow](http://stackoverflow.com/questions/tagged/git), and the [git cheat sheet](http://cheat.errtheblog.com/s/git/).