<sup>*The shortlink to this wiki page is https://r-7.co/MSF-DEV*</sup>

This is a guide for setting up a developer environment to contribute modules, documentation, and fixes to the Metasploit Framework. If you just want to use Metasploit for legal, authorized hacking, we recommend instead you:

 - Install the [open-source Omnibus installer][open-source-installer], or
 - Use the pre-installed Metasploit on [Kali Linux][kali-user-instructions] or [Parrot Linux][parrot-user-instructions].

If you want to contribute to Metasploit, start by reading our [CONTRIBUTING.md], then follow the rest of this guide.


## Assumptions

* You have installed an apt-based Linux environment, such as [Ubuntu] or [Kali].
* You have created a GitHub account and associated an [ssh key][ssh-key] with it.
* You have familiarity with Git and Github, or have completed the [Github bootcamp][github-bootcamp].
* For optional database and REST API functionality, you will need regular user account that is not `root`.


## Install dependencies

1. Open a terminal on your Linux host and set up Git, build tools, and Ruby dependencies:

```bash
sudo apt update && sudo apt install -y git autoconf build-essential libpcap-dev libpq-dev zlib1g-dev libsqlite3-dev
```


## Set up your local copy of the repository

You will need to use Github to create a fork for your contributions and receive the latest updates from our repository.

1. Login to Github and click the "Fork" button in the top-right corner of the [metasploit-framework] repository.

2.  Create a `git` directory in your home folder and clone your fork to your local machine:

```bash
export GITHUB_USERNAME=YOUR_USERNAME_FOR_GITHUB
export GITHUB_EMAIL=YOUR_EMAIL_ADDRESS_FOR_GITHUB
mkdir -p ~/git
cd ~/git
git clone git@github.com:$GITHUB_USERNAME/metasploit-framework
cd ~/git/metasploit-framework
```

3. If you encounter a "permission denied" error on the above command, research the error message.  If there isn't an explicit reason given, confirm that your [Github SSH key is configured correctly][github-ssh-instructions].

4. To receive updates, you will create an `upstream-master` branch to track the Rapid7 remote repository, alongside your `master` branch which will point to your personal repository's fork:

```bash
git remote add upstream git@github.com:rapid7/metasploit-framework.git
git fetch upstream
git checkout -b upstream-master --track upstream/master
```

5. Configure your Github username, email address, and username.  Ensure your `user.email` matches the email address you registered with your Github account.

```bash
git config --global user.name "$GITHUB_USERNAME"
git config --global user.email "$GITHUB_EMAIL"
git config --global github.user "$GITHUB_USERNAME"
```

6. Set up [msftidy] to run before each `git commit` and after each `git merge` to quickly identify potential issues with your contributions:

```bash
cd ~/git/metasploit-framework
ln -sf ../../tools/dev/pre-commit-hook.rb .git/hooks/pre-commit
ln -sf ../../tools/dev/pre-commit-hook.rb .git/hooks/post-merge
```

## Install Ruby

Linux distributions do not ship with the latest Ruby, nor are package managers routinely updated.  Additionally, if you are working with multiple Ruby projects, each one has dependencies and Ruby versions which can start to conflict.  For these reasons, it is advisable  to use a Ruby manager.

You could just install Ruby directly (eg. `sudo apt install ruby-dev`), but you may likely end up with the incorrect version and no way to update.  Instead, consider using one of the many different [Ruby environment managers] available.  The Metasploit team prefers [rbenv] and [rvm].

Regardless of your choice, you'll want to make sure that, when inside the `~/git/metasploit-framework` directory, you are running the correct version of Ruby:

```
$ cd ~/git/metasploit-framework
$ cat .ruby-version 
2.5.3
$ ruby -v
ruby 2.5.3p105 (2018-10-18 revision 65156) [x86_64-linux-gnu]
```

Note: the Ruby version is likely to change over time, so don't rely on the output in the above example.  Instead, confirm your `ruby -v` output with the version number listed in the `.ruby-version` file.

If the two versions don't match, restart your terminal. If that does not work, consult the troubleshooting documentation for your Ruby environment manager.  Unfortunately, troubleshooting the Ruby environment is beyond the scope of this document, but feel free to reach out for community support using the links at the bottom of this document.


## Install Gems

1. Before you run Metasploit, you will need to update the gems (Ruby libraries) that Metasploit depends on:

```
cd ~/git/metasploit-framework/
gem install bundler
bundle install
```

2. If you encounter an error with the above command, refer to the `bundle` output and search for the error message along with the name of the gem that failed. Likely, you'll need to `apt get install` a dependency that is required by that particular gem.  If it was something else, open a [new issue] to let us know what happened.

Congratulations! You have now set up a development environment and the latest version of Metasploit.


## Optional: Set up the REST API and PostgreSQL database

<details><summary>The following optional section describes how to manually install PostgreSQL and set up the Metasploit database.  Alternatively, use our Omnibus installer which handles this more reliably.  Click to expand.</summary>

1. Confirm that the PostgreSQL server and client are installed:

```bash
sudo apt update && sudo apt-get install -y postgresql postgresql-client
sudo service postgresql start && sudo update-rc.d postgresql enable
```

2. Ensure that you are not running as the root user.

3. Initialize the Metasploit database:

```bash
cd ~/git/metasploit-framework
./msfdb init
```

4. If you receive an error about a component not being installed, confirm that the binaries shown are in your path using the [which] and [find] commands, then modifying your [$PATH] environment variable.  If it was something else, open a [new issue] to let us know what happened.

5. If the `msfdb init` command succeeds, then confirm that the database is accessible to Metasploit:

```bash
$ ./msfconsole -qx "db_status; exit"
```

Congratulations! You have now set up the [Metasploit Web Service (REST API)][msf-web-service] and the backend database.

</details>

## Optional: Tips to speed up common workflows

<details><summary>The following section is optional but may improve your efficiency.  Click to expand.</summary>

- Making sure you're in the right directory to run `msfconsole` can become tedious, so consider using the following Bash alias:

```bash
echo 'alias msfconsole="pushd $HOME/git/metasploit-framework && ./msfconsole && popd"' >> ~/.bash_aliases
```

 - Consider generating a GPG key to sign your commits.  Read about [why][git-horror] and [how][signing-howto].

 - Developers tend to customize their own [git aliases] to speed up common commands, but here are a few common ones:

```rc
[alias]
# An easy, colored oneline log format that shows signed/unsigned status
nicelog = log --pretty=format:'%Cred%h%Creset -%Creset %s %Cgreen(%cr) %C(bold blue)<%aE>%Creset [%G?]'

# Shorthand commands to always sign (-S) and always edit the commit message.
m = merge -S --no-ff --edit
c = commit -S --edit

# Shorthand to always blame (praise) without looking at whitespace changes
b= blame -w
```

 - If you plan on working with other contributor's pull requests, you may run the following script which makes it easier to do so:

```
tools/dev/add_pr_fetch.rb
```

  After running the above script, you can `checkout` other pull requests more easily:

```
git fetch upstream
git checkout fixes-to-pr-12345 upstream/pr/12345
```

 - If you're writing test cases (which you should), then make sure [rspec] works:

```bash
rake spec
```

You should see over 9000 tests run, mostly resulting in green dots, a few in yellow stars, and no red errors.

</details>
 
# Great!  Now what?

We're excited to see your upcoming contributions of new modules, documentation, and fixes!  Check out our [wiki documentation][wiki-documentation] and, if you're looking for inspiration, keep an eye out for [newbie-friendly pull requests and issues][newbie-friendly-prs-issues].   Please [submit your new pull requests][howto-PR] and reach out to us on [Slack] for community help.

Finally, we welcome your feedback on this guide, so feel free to reach out to us on [Slack] or open a [new issue].  For their significant contributions to this guide, we would like to thank [@kernelsmith], [@corelanc0d3r], and [@ffmike].

[commercial-installer]:http://metasploit.com/download
[open-source-installer]:https://github.com/rapid7/metasploit-framework/wiki/Nightly-Installers
[kali-user-instructions]:https://docs.kali.org/general-use/starting-metasploit-framework-in-kali
[parrot-user-instructions]:https://docs.parrotsec.org/doku.php/metasploit-framework#start-metasploit
[CONTRIBUTING.md]:https://github.com/rapid7/metasploit-framework/blob/master/CONTRIBUTING.md

[Ubuntu]:https://www.ubuntu.com/download/desktop
[Kali]:https://www.kali.org/downloads/
[Parrot]:https://www.parrotsec.org/download-security.php
[ssh-key]:https://help.github.com/articles/generating-ssh-keys/
[github-bootcamp]:https://help.github.com/articles/set-up-git/

[metasploit-framework]:https://github.com/rapid7/metasploit-framework/
[github-ssh-instructions]:https://help.github.com/articles/adding-a-new-ssh-key-to-your-github-account/
[msftidy]:https://www.oreilly.com/library/view/metasploit-revealed-secrets/9781788624596/91660ab9-a260-4de8-a4ea-c1af64eafbec.xhtml

[Ruby environment managers]:https://www.ruby-lang.org/en/documentation/installation/#managers
[rvm]:https://github.com/rvm/ubuntu_rvm#install
[rbenv]:https://github.com/rbenv/rbenv#basic-github-checkout

[which]:https://linux.die.net/man/1/which
[find]:https://linux.die.net/man/1/find
[$PATH]:https://askubuntu.com/questions/109381/how-to-add-path-of-a-program-to-path-environment-variable

[msf-web-service]:https://github.com/rapid7/metasploit-framework/wiki/Metasploit-Web-Service

[git-horror]:https://mikegerwitz.com/papers/git-horror-story#trust-ensure
[signing-howto]:https://github.com/rapid7/metasploit-framework/wiki/Committer-Keys#signing-howto

[git aliases]:https://git-scm.com/book/en/v2/Git-Basics-Git-Aliases
[rspec]:https://www.rubyguides.com/2018/07/rspec-tutorial/
[wiki-documentation]:https://github.com/rapid7/metasploit-framework/wiki#metasploit-development
[newbie-friendly-prs-issues]:https://github.com/rapid7/metasploit-framework/issues?q=is%3Aopen+label%3Anewbie-friendly
[howto-PR]:https://help.github.com/articles/about-pull-requests/
[new issue]:https://github.com/rapid7/metasploit-framework/issues/new
[Slack]:https://www.metasploit.com/slack
[@kernelsmith]:https://github.com/kernelsmith
[@corelanc0d3r]:https://github.com/corelanc0d3r
[@ffmike]:https://github.com/ffmike