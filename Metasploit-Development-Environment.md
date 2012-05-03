# Metasploit Development Environment
The Metasploit Framework is a pretty complex hunk of software, at least according to [Ohloh](http://www.ohloh.net/p/metasploit). So, getting started with development can be daunting even for veteran exploit developers. This page attempts to demystify the process of getting your Metasploit development environment set up through submitting a "pull request" to get your exploit into the standard distribution.

## Your Development Platform

This documentation assumes you're on some recent version of Ubuntu Linux. If not, then you're going to be on your own on how to get all your dependencies lined up. If you've successfully set up a development environment on something non-Ubuntu, and you'd like to share, let us know and we'll link to your tutorial from here.

A lot of people, including many of Metasploit's core developers, like to maintain a dedicated VMWare image for development. There are advantages to this that are difficult to replicate with other backup and restore solutions.

### Apt-get install

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

### RVM

Most (all?) standard distributions of Ruby are lacking in one regard or another. Lucky for all of us, RVM has been getting steadily more excellent in providing several proven Ruby interpreters. Visit [https://rvm.io/](https://rvm.io/) to read up on it, or just trust that it'll all work out with a simple:

````bash
curl -L get.rvm.io | bash -s stable
````

Followed by 

````bash
source ~/.rvm/scripts/rvm
````
You should end up with something akin to this:

### Vim configuration

Coming soon!

### Emacs configuration

Coming slightly later!

***

## Create a GitHub Account

The entire Metasploit code base is hosted here on GitHub. If you have an old Redmine account over at dev.metasploit.com, that's not going to do much for you since the switch-over. The process for creating an account is pretty simple:

###  SSH for GitHub

***

## Working with Git

### Forking

### Keeping in sync

### Pull Requests

***

## More lnformation and Feedback