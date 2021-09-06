# Some Terminology

In this quick HOWTO, we'll be referring to the `rapid7` fork of `metasploit-framework` as `upstream`. It's a pretty common local configuration, advocated by the [development environment setup](http://r-7.co/MSF-DEV). Your fork of `metasploit-framework` will be referred to as `origin`.

The term 'repo' is short for 'Repository.' Also known as 'fork' (as a noun).

## The Easy Way

The easiest way to keep in sync with master is to trash your fork of `metasploit-framework`, and re-fork. This is a surprisingly common practice, since most people in the world don't work with Metasploit every day. If you're the sort to be struck by hackerish inspiration every few months, and couldn't give a whit about preserving branches, history, or pull requests, simply nuke your local fork.

On your fork, in the GitHub UI, go to **Settings**, scroll down to the **Danger Zone**, and hit **Delete this repository**. Once you've re-authenticated, re-fork the `metasploit-framework` repository by going to the [Rapid7 repo](https://github.com/rapid7/metasploit-framework) and hit **Fork** as hard as you possibly can.

## The Hard Way

If you're contributing to the Metasploit Framework a lot, first off, THANK YOU. Metasploit is more than a framework, it's a collective and a community of people around the world who are driven to make the Internet -- and therefore, human civilization -- a better place.

Gushing aside, if you want to keep in sync with upstream, the hard way (and therefore, best way), is to have a local clone of `origin/mestasploit-framework` on your local workstation. (Linux is preferred, but there are servicable solutions for OSX and Windows).

And, with *that* said, the GitHub documentation is pretty excellent in explaining how to do this -- it's really not all that hard. Take a look at their [Fork A Repo](https://help.github.com/articles/fork-a-repo/) docs, and do what it says.

One thing I like to do is to keep separate branches for `master` (which tracks `origin/master`), and `upstream-master` (which tracks, unsurprisingly, `upstream/master`). If you just want to know how to add an `upstream` remote, [check it out](https://help.github.com/articles/configuring-a-remote-for-a-fork/). Once you've done that, all you need to do is to pull one of these:

```
git checkout -b upstream-master --track upstream/master
git checkout master
git merge --ff-only upstream-master
git commit
git push origin
```

Now, this only works well if you **never commit to master**. If you do, you're going to have a bad time, as you'll eventually hit a dreaded [merge conflict](https://help.github.com/articles/resolving-merge-conflicts/).

Any change you make, be it for local experimentation or public proposal, should be done in a branch *from* the `master` branch (or, if you're a habitual committer, a branch off the `upstream-master` branch).

Ignore this advice at your own peril.

## The Max Powers Way

*It's like the wrong way, but faster.*
*- Max Powers*

If you are allergic to the command line, it *is possible* to sync with upstream/master via the GitHub web UI. This is a little messy, but it's handy if you have small changes that you don't care to sign (by the way, [you should sign your commits](http://mikegerwitz.com/papers/git-horror-story)).

First, go to the [Rapid7 branch](https://github.com/rapid7/metasploit-framework), and click the green, somewhat subtle mini-PR button. Then, click **Compare across forks**, and set **base fork** to your fork, while leaving the head fork pointing to Rapid7's fork. That'll take you to a URL like this: `https://github.com/rapid7/metasploit-framework/compare/YOURGITHUBNAME:master...master`

Next, you'll hit the big green **Create a Pull Request** button, which will drop you to a new PR page, against your own fork. Fill it in, then immediately click the **PRs** icon on the left side, find your new PR, and merge it.

This will keep your GitHub-hosted fork up-to-date, and if you prefer using the GitHub UI over a real development environment, you can jump in and start making changes there.

This method is especially handy for light changes, like documentation or cosmetic changes to modules. However, using the GitHub UI means that you are necessarily not testing new modules or libraries, and you of course cannot sign your commits, which is [horrifying](http://mikegerwitz.com/papers/git-horror-story). It's also nice for people very new to GitHub as a collaborative platform.


