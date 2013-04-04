# Landing Pull Requests

Metasploit is built incrementally by the community through GitHub's [Pull Request](https://github.com/rapid7/metasploit-framework/pulls) mechanism. Submitting pull requests (or PRs) is already discussed in the [Dev environment setup](https://github.com/rapid7/metasploit-framework/wiki/Setting-Up-a-Metasploit-Development-Environment) documentation. It's important to realize that PRs are a feature of GitHub, not git, so this document will take a look at how to get your git environment to deal with them sensibly.

# The short story

 - Add the `fetch = +refs/pull/*/head:refs/remotes/origin/pr/*` line to your .git/config
 - Always, always `merge --no-ff` so you can reference the PR number.
 - Merge to a landing branch, then merge *that* to master, so you can isolate your work.
 - Often you need to make changes. Examples coming soon!

# Prep your local clone.

For the purposes of this document, we'll assume that the "origin" repository is the Rapid7 repository. You should still be doing most of your work in your own fork of Metasploit, but if you have commit rights, you'll want to make Rapid7 the origin.

In your `.git/config` file, you will have a stanza like this, assuming `github-r7` is defined in your .ssh/config:

````config
[remote "origin"]
	fetch = +refs/heads/*:refs/remotes/origin/*
	url = github-r7:rapid7/metasploit-framework
````

Add to that the magical PR fetch line, so it looks like this:

````config
[remote "origin"]
	fetch = +refs/heads/*:refs/remotes/origin/*
	fetch = +refs/pull/*/head:refs/remotes/origin/pr/*
	url = github-r7:rapid7/metasploit-framework
````

You can do the same for your own fork easily enough as well. Mine looks like:

````config
[remote "todb-r7"]
	url = github-r7:todb-r7/metasploit-framework
	fetch = +refs/heads/*:refs/remotes/todb-r7/*
	fetch = +refs/pull/*/head:refs/remotes/todb-r7/pr/*
````

Now, when you type `git fetch`, you'll get refs pointing at all (open *and* closed) Pull Requests. Just this moment, I see something like this:

````
$ git fetch
remote: Counting objects: 91, done.
remote: Compressing objects: 100% (29/29), done.
remote: Total 59 (delta 47), reused 42 (delta 30)
Unpacking objects: 100% (59/59), done.
From github-r7:rapid7/metasploit-framework
   b6a50da..1344fa8  refs/pull/1651/head -> origin/pr/1651
   2b4d6eb..7b4cdf4  refs/pull/1669/head -> origin/pr/1669
   8032a33..78c492d  refs/pull/1676/head -> origin/pr/1676
 * [new ref]         refs/pull/1701/head -> origin/pr/1701
 * [new ref]         refs/pull/1702/head -> origin/pr/1702
````

# Pre-merge testing

Since we don't just merge blindly, create a local branch for testing, and merge there. Something like so:

````
(master) todb@mazikeen:~/git/rapid7/metasploit-framework
$ git pull -r
Current branch master is up to date.
(master) todb@mazikeen:~/git/rapid7/metasploit-framework
$ git checkout -b landing-pr1702
Switched to a new branch 'landing-pr1702'
(landing-pr1702) todb@mazikeen:~/git/rapid7/metasploit-framework
$ git merge --no-ff origin/pr/1702
Merge made by the 'recursive' strategy.
 .../postgres/postgres_dbname_flag_injection.rb     |   75 ++++++++++++++++++++
 1 file changed, 75 insertions(+)
 create mode 100644 modules/auxiliary/scanner/postgres/postgres_dbname_flag_injection.rb
(landing-pr1702) todb@mazikeen:~/git/rapid7/metasploit-framework
$ 
````

What this does is get your local checkout up to date (`pull -r`), create a new branch off of master (`git checkout -b landing-pr1702`), and merge the PR with no fast-forward. Note the two useful features of this strategy. First, we merge the PR without needing to set up any extra remotes. Second, we force `-no-ff`, which is "no fast forward," ensuring we get a merge commit message (often, small changes will *not* create merge commits by default). We can now merge commit with a meaningful message:

````
Landing #1702, hdmoore's postgres scanner

# Please enter a commit message to explain why this merge is necessary,
# especially if it merges an updated upstream into a topic branch.
# 
# Lines starting with '#' will be ignored, and an empty message aborts
# the commit.
````

When viewing [this commit](https://github.com/rapid7/metasploit-framework/commit/cb874390488ed03464e717d121f620ce6c97d71b) in GitHub, we get a nice syntax highlight back to the original Pull Request (click it, and see!). This way, we don't lose whatever discussion happened around this new feature or bugfix. In addition, we can edit this commit message it later when we're ready to merge it for real.

# Test and make any suggestions.

Once you've merged to your landing branch, run `rake spec` to make sure all the tests still pass. (You will need to `bundle install` at some point to ensure you can actually run the specs).

````
$ rake spec
# Lots of test results
Finished in 40.07 seconds
710 examples, 0 failures, 20 pending
````

If you're merging a module, then you'll want to check in with `msftidy` as well:

````
(landing-pr1702) todb@mazikeen:~/git/rapid7/metasploit-framework
$ git diff --name-only master
modules/auxiliary/scanner/postgres/postgres_dbname_flag_injection.rb
$ tools/msftidy.rb modules/auxiliary/scanner/postgres/postgres_dbname_flag_injection.rb
````

Then, review the code, make sure everything's great.

# Merge to master

````
(landing-pr1702) todb@mazikeen:~/git/rapid7/metasploit-framework
$ git checkout master
Switched to branch 'master'
(master) todb@mazikeen:~/git/rapid7/metasploit-framework
$ git merge landing-pr1702 
Updating e4d901d1..cb87439
Fast-forward
 .../postgres/postgres_dbname_flag_injection.rb     |   75 ++++++++++++++++++++
 1 file changed, 75 insertions(+)
 create mode 100644 modules/auxiliary/scanner/postgres/postgres_dbname_flag_injection.rb
(master) todb@mazikeen:~/git/rapid7/metasploit-framework
````

In this case, since we already have a meaningful merge commit, we can safely fast-forward. Note that the log looks just fine:

````
$ git log
commit cb874390488ed03464e717d121f620ce6c97d71b
Merge: e4d901d1 fe2b598
Author: Tod Beardsley <todb@metasploit.com>
Date:   Thu Apr 4 10:38:20 2013 -0500

    Landing #1702, hdmoore's postgres scanner

commit fe2b5985038fc60a4dad014a64d519da90a18916
Author: HD Moore <hd_moore@rapid7.com>
Date:   Thu Apr 4 10:22:31 2013 -0500

    Add the advisory URL

commit c8a6dfbda2d991ad5a9895e67792e3f040031539
Author: HD Moore <hd_moore@rapid7.com>
Date:   Thu Apr 4 10:19:47 2013 -0500

    Add scanner module for the new PostgreSQL flaw
````

If we want to make any final changes to the merge commit, now's the time:

````
$ git commit --amend
````

````
Landing #1702, hdmoore's postgres scanner

Code looks good to me, screenshot provided on PR #1702.

[Closes #1702]
````

You never want to amend a commit once you've pushed it up to the remote -- doing so will change history and cause conflicts for anyone who's gotten a hold of your original commit. Before you push, though, feel free.

Finally, push it up:

````
(master) todb@mazikeen:~/git/rapid7/metasploit-framework
$ git push origin master 
Counting objects: 1, done.
Writing objects: 100% (1/1), 238 bytes, done.
Total 1 (delta 0), reused 0 (delta 0)
To github-r7:rapid7/metasploit-framework
   e4d901d1..cb87439 master -> master
(master) todb@mazikeen:~/git/rapid7/metasploit-framework
$ 
````

# That's it?

When things are easy, yes, that's it. The procedure above was written against a particularly safe, low-risk PR, [#1702](https://github.com/rapid7/metasploit-framework/pull/1702), and you can see the results there.

If we had a [Redmine bug](https://dev.metasploit.com/redmine/projects/framework/issues?query_id=420) we were working against, we'd mention it in the final commit message as well, and we'd get a cross-reference over in Redmine:

````
Wow, glad this is fixed!

[FixRM #1234]
````

However, things are rarely that straightforward. The next few examples will detail when things need fixing along the way. Since this doc is being writing against live, real examples, we'll need to wait a sec for these examples to come up.

# When you want to make changes

Rarely are pull requests landed without modification.

## When the changes are simple

*Give an example of just editing in landing-XXXX and then merging from there. Not complicated.*

## When you have feedback

*Give an example of comments on the PR that cause the contributor to make changes.*

## When the changes are complex

*Give an example of issuing a pull request back to the contributor*

## When you hit a merge conflict

*Give an example of untangling a merge conflict*

## More examples?

*Other cases?*