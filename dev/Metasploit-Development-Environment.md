# Metasploit Development Environment

The Metasploit Framework is a pretty complex hunk of software, at least according to [Ohloh](http://www.ohloh.net/p/metasploit). So, getting started with development can be daunting even for veteran exploit developers. This page attempts to demystify the process of getting your Metasploit development environment set up through submitting a "pull request" to get your exploit into the standard distribution.

This documentation assumes you're on some recent version of Ubuntu Linux. If not, then you're going to be on your own on how to get all your dependencies lined up. If you've successfully set up a development environment on something non-Ubuntu, and you'd like to share, let us know and we'll link to your tutorial from here.

Throughout this documentation, we'll be using the example user of "Fakey McFakepants," who has the e-mail address of "mcfakepants@packetfu.com" and a login username of "fakey."



<h2 id="apt">Apt-Get Install</h2>

The bare minimum for working on Metasploit effectively is:

````bash
apt-get -y install \
  build-essential zlib1g zlib1g-dev \
  libxml2 libxml2-dev libxslt-dev locate \
  libcurl4-openssl-dev git-core \
  libssl-dev openssl autoconf bison curl wget \
  postgresql postgresql-contrib libpq-dev
````

Note that this does **not** include an appropriate text editor or IDE, nor does it include the Ruby interpreter itself. We'll get to that in a second.

<h2 id="rvm">RVM</h2>

Most (all?) standard distributions of Ruby are lacking in one regard or another. Lucky for all of us, Wayne Seguin's RVM has been getting steadily more excellent in providing several proven Ruby interpreters. Visit [https://rvm.io/](https://rvm.io/) to read up on it, or just trust that it'll all work out with a simple:

````bash
$ curl -L get.rvm.io | bash -s stable
````

Followed by 

````bash
$ source ~/.rvm/scripts/rvm
````

And finally:

````bash
$ rvm install 1.9.3-p125
````

What this all does is fetch RVM, which performs a bunch of shell voodoo, and finally installs Ruby version 1.9.3 patchlevel 125 (there are lots of other Rubies to choose from, but we like this one the most right now). Assuming all goes as planned, you should end up with something like this in your shell.

[[/screens/rvm02.png]]

<h2 id="editor">Editor / IDE</h2>

Once that's all done, you can move on to setting up your preferred editor. Far be it from us to tell you what editor you use -- people get really attached to these things for some reason. Once we have some docs put together for sensible defaults for a couple of the more popular editors out there, we'll list that here.

<h2 id="github">Create a GitHub Account</h2>

The entire Metasploit code base is hosted here on GitHub. If you have an old Redmine account over at dev.metasploit.com, that's not going to do much for you since the switch-over. The process for creating an account is pretty simple.

### Find the Signup button

[[/screens/new01.png]]

### Create a free user

[[/screens/new02.png]]

### Come up with a decent username and password

[[/screens/new04.png]]

None of this is exactly rocket science.

<h2 id="ssh">SSH for GitHub</h2>

Once that's all done, you need to set up an SSH key to associate with your new GitHub identity (this step is **not** optional, so good on GitHub for forcing this minimal level of security).

### Create a new key

The Metasploit core developers recommend you set up new SSH key pair to associate with GitHub, rather than reuse that same old tired key you have in 50 other authorized_keys files around the world. Why not just start fresh? It's easy and fun:

````bash
$ ssh-keygen -t -rsa -C "mcfakepants@packetfu.com"
````
Just follow the prompts, pick a name for your key pair (I use "id_rsa.github"), set a password, and you should end up with something like:

[[/screens/ssh01.png]]

### Add your key

Next, go to [https://github.com/settings/ssh](https://github.com/settings/ssh) (which can be navigated to via _Account Settings > SSH Keys_), and click "Add SSH key" :

[[/screens/ssh02.png]]

You'll be presented with a screen to copy-paste your public SSH key (not the private one!). Easiest thing to do is to cat your newly created key, select, and copy-paste it:

[[/screens/ssh03.png]]

[[/screens/ssh04.png]]

### Confirm your key

Once that's done, you'll have a key associated, and you'll get e-mail about it as well. Eyeball the fingerprint and make sure it all matches up. 

[[/screens/ssh05.png]]

The real moment of truth is when you test your SSH key. If you named it something funny like I did, don't forget the -i flag, use -T to avoid allocating a terminal (you won't get one anyway), and note that you are going to use literally "git@github.com" as the username (not your name or anything like that).

````bash
$ ssh -i ~/.ssh/id_rsa.github -T git@github.com
````
Your console should look like:

[[/screens/ssh07.png]]

### Alias GitHub in .ssh/config

I hate having to remember usernames for anything anymore, so I've gotten in the habit of creating Host entries for lots of things in my ~/.ssh/config file. You should try it, it's fun and it can shorten most of your ssh logins to two words.

For the rest of these instructions, I'm going to assume you have something like this in yours:

````config
Host github
  Hostname github.com
  User git
  PreferredAuthentications publickey
  IdentityFile ~/.ssh/id_rsa.github
````
To check that it works, just `ssh -T github`, and your result should be just like this:

[[/screens/ssh10.png]]

### Minimal Git config

Finally, you're ready to set up your local git config file, if you haven't already:

````bash
git config --global user.name "Fakey McFakepants"
git config --global user.email "mcfakepants@packetfu.com"
````

Cat your ~/.gitconfig to ensure you have at least that set (and remember, your e-mail address needs to match the address you set back when you ssh-keygen'ed):

[[/screens/ssh11.png]]

<h1 id="git">Working with Git</h2>

The rest of this document will walk through the usual use case of working with Git and GitHub to get a local source checkout, commit something new, and get it submitted to be part of the Metasploit Framework distribution. The example here will commit the file _2.txt_ to _test/git/_ , but imagine that we're committing some new module like _ms_12_020_code_exec.rb_ to _modules/exploits/windows/rdp/_.

<h2 id="fork">Forking Metasploit</h2>

Now that you have a GitHub account, it's time to fork the Metasploit Framework. First, go to https://github.com/rapid7/metasploit-framework , and click the button:

[[/screens/fork01.png]]

Hang out for a few seconds, and behold the animated "Hardcore Forking Action:"

[[/screens/fork02.png]]

Once that's done, switch back over to your terminal, make a subdirectory for your git clones, and use your previously defined .ssh/config alias to clone up a copy of Metasploit:

````bash
$ mkdir git
$ cd git
$ git clone github:mcfakepants/metasploit-framework.git
````
You should end up with a complete copy of Metasploit in the metasploit-framework subdirectory, like so:

[[/screens/fork03.png]]

<h3 id="prompt">Set Your Prompt</h3>

Now might be a good time to decorate up your prompt. I've hacked this together for my ~/.bash_aliases. It's a little ugly, but it works:

<script src="https://gist.github.com/2555109.js"> </script>

What this does is let me know on the command line prompt which version of Ruby, which gemset, and which Git branch I happen to be in. The end result looks like this:

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

It's pretty handy to have this checkout be persistent, though, so you can reference it later. So, type this:

````bash
$ git checkout -b upstream-master
````

And this will create a new branch called "upstream-master." Now, switch back to your master branch and fetch anything new from there:

````bash
$ git checkout master
$ git fetch
````

And finally, rebase against the upstream. Rebasing is the easiest way to make sure that your master branch is identical to the upstream master branch. If you have any local changes, those are "rewound," all the remote changes get laid down, and then your changes get reapplied. It should all look like this:

[[/screens/git03.png]]

Of course, you might occasionally run into rebase conflicts, but let's just assume you won't for now. :) (See the "Other links" for dealing with merge and rebase conflicts.)

#### A Note on Terminology

In Git, we often refer to "origin" and "master," which can be confusing. "Origin" is a remote repository which contains all of **your** branches. "Master" is a branch of the source code -- usually the first branch, and the branch you don't tend to commit directly to. 

"Origin" **isn't** Rapid7's repository -- we usually referred to that repo as "Upstream." In other words, "upstream" is just another way of referring to the "rapid7" remote. 

Got it? "Origin" is your repo up at GitHub, "upstream" is Rapid7's GitHub repo, and "master" is the primary branch of their respective repos.

All right, moving on.

### Syncing changes

Any time you rebase from upstream, you're likely to bring in new changes, since we're committing stuff all the time. This means that when you rebase, your local branch will be ahead of your remote branch. To get your remote up to speed, just

````bash
$ git push origin master
````

It should all look something like this:

[[/screens/git04.png]]

Switch back to your browser, refresh, and you should see the new changes reflected in your repo immediately (those GitHub guys are super fast):

[[/screens/git05.png]]

<h2 id="pull">Pull Requests</h2>

Stuff about pull requests

***

## More lnformation and Feedback