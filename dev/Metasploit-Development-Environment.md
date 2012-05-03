# Metasploit Development Environment

The Metasploit Framework is a pretty complex hunk of software, at least according to [Ohloh](http://www.ohloh.net/p/metasploit). So, getting started with development can be daunting even for veteran exploit developers. This page attempts to demystify the process of getting your Metasploit development environment set up through submitting a "pull request" to get your exploit into the standard distribution.

This documentation assumes you're on some recent version of Ubuntu Linux. If not, then you're going to be on your own on how to get all your dependencies lined up. If you've successfully set up a development environment on something non-Ubuntu, and you'd like to share, let us know and we'll link to your tutorial from here.

Throughout this documentation, we'll be using the example user of "Fakey McFakepants," who has the e-mail address of "mcfakepants@packetfu.com" and a login username of "fakey."

## <a name="apt-get">Apt-Get Install</a>

The bare minimum for working effectively on Metasploit is:

````
apt-get -y install \
  build-essential zlib1g zlib1g-dev \
  libxml2 libxml2-dev libxslt-dev locate \
  libcurl4-openssl-dev git-core \
  libssl-dev openssl autoconf bison curl wget \
  postgresql postgresql-contrib libpq-dev
````

Note that this does **not** include an appropriate text editor or IDE, nor does it include the Ruby interpreter itself. We'll get to that in a second.

## RVM

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

Once that's all done, you can move on to setting up your preferred editor. There are lots of tricks involved there, so soon we'll have guides for setting up at least vim and emacs (the two most popular editors for working in Metasploit).

## Create a GitHub Account

The entire Metasploit code base is hosted here on GitHub. If you have an old Redmine account over at dev.metasploit.com, that's not going to do much for you since the switch-over. The process for creating an account is pretty simple:

###  SSH for GitHub

## Working with Git

### Forking

### Keeping in sync

### Pull Requests

***

## More lnformation and Feedback