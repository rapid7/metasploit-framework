## Fork the Metasploit repo

First things first, if you haven't already, you'll need to [fork the Metasploit Framework repo](http://help.github.com/fork-a-repo/). Head on over to [[https://github.com/rapid7/metasploit-framework]] and click the "Fork" button to make it happen.

<img src="http://help.github.com/images/bootcamp/bootcamp_3_fork.jpg" width="558" height="137" alt="Click &ldquo;Fork&rdquo;"  />

Now you just need to clone your copy of the framework code to your local machine and add a remote reference back to the upstream repo to pull in new commits.

```console
$ git clone git@github.com:techpeace/metasploit-framework.git
Cloning into 'metasploit-framework'...
remote: Counting objects: 117417, done.
remote: Compressing objects: 100% (29898/29898), done.
remote: Total 117417 (delta 83824), reused 117349 (delta 83756)
Receiving objects: 100% (117417/117417), 110.61 MiB | 667 KiB/s, done.
Resolving deltas: 100% (83824/83824), done.
$ cd metasploit-framework
$ git remote add upstream git://github.com/rapid7/metasploit-framework.git
```

## Create a topic branch

It's best to keep all work organized into (topic branches)[http://progit.org/book/ch3-4.html]. To start a topic branch, make sure you're on the master branch, pull in changes from up stream, and check out a new branch.

```console
$ git checkout master
Already on 'master'
$ git pull upstream master
From git://github.com/rapid7/metasploit-framework
 * branch            master     -> FETCH_HEAD
Already up-to-date.
$ git checkout -b add-my-awesome-module
Switched to a new branch 'add-my-awesome-module'
```

From here, you can hack away and commit to your new branch as many times as you'd like.

## Create a pull request

Once you've got everything the way you'd like it in your topic branch, you'll need to create a [pull request](http://help.github.com/send-pull-requests/) to get your work merged back in to the main Metasploit repo. Start by pushing your branch up to your fork on GitHub.

```console
$ git push origin my-awesome-module
Counting objects: 4, done.
Delta compression using up to 2 threads.
Compressing objects: 100% (2/2), done.
Writing objects: 100% (3/3), 275 bytes, done.
Total 3 (delta 1), reused 0 (delta 0)
To git@github.com:techpeace/metasploit-framework.git
 * [new branch]      my-awesome-module -> my-awesome-module
```

Now access your fork on GitHub and switch to your new branch from the *Switch Branches* menu. From there, click the *Pull Request* button at the top of the page.

![Click the Pull Request button](http://img.skitch.com/20100831-qfk1c9wyt89pfgfxg61bh1r8rn.png)

Review the [excellent information provided by GitHub on configuring pull requests](http://help.github.com/send-pull-requests/), and then click the big friendly *Send Pull Request* button at the bottom of the page when you're ready for the team to review your code. After that, you'll either get feedback from the team on further changes to be made, or your code will be merged into the framework.

## Do small dance of celebration

That's it! Thanks for doing your part to make Metasploit the best pentesting framework on the planet.



