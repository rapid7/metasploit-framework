Since the Metasploit-framework repository's master branch is the bleeding edge of development, occasionally mistakes happen. This page will attempt to give some guidance on how to roll back a bad merge.

# What's a bad merge?

 * Anything that causes [Travis-CI](travis-ci.org/rapid7/metasploit-framework/builds) to fail rspec tests consistently.
 * Anything that hits untested code that otherwise causes problems with `msfconsole`, `msfcli`, `msfvenom`, and other console commands.

Sometimes, Travis-CI does choke up, due to network weather. Every build is a fresh clone, and all gems have to be reinstalled every time. Also, some rspec tests require network connections to assets on the Internet. Sometimes, Travis-CI itself is under a lot of load, and builds time out.

The best way to diagnose these problems is simply to restart the build. Note, only [Committers](https://github.com/rapid7/metasploit-framework/wiki/Committer-Rights) have rights to do this. If that doesn't clear things up, or if it's obvious that there are real failures (since you've read the rspec results and have read the tests), the first order of business is to undo your bad commit.

**Note**: in branches other than `master`, you can usually just fix things normally with new commits. There are plenty of "whoops" commit messages in our history.

# A merge revert example

Once, there was a bad merge on [PR #2320](https://github.com/rapid7/metasploit-framework/pull/2320). The fellow landing this pull request ran into a merge conflict while landing, thought he fixed it, and pushed the results, which ended up breaking about a dozen Rspec tests. Whoops. That was a bad merge. [PR #2624](https://github.com/rapid7/metasploit-framework/pull/2624) fixed it. Here's the procedure used.

### Figure out what broke things.

In this case, the failed build was pretty obvious: [Build #5216](https://travis-ci.org/rapid7/metasploit-framework/builds/13816889) was red, and rerunning Travis-CI didn't solve. Reading the build log, we can see this was [merge commit 3996557](http://github.com/rapid7/metasploit-framework/commit/3996557ec61a6eeefaa3448480012205b8825374).

### Check out the bad merge tip.

These commands will put the local repo back to the bad merge, and create a local branch as such:

`git checkout 3996557`
`git checkout -b bad-merge`

You can inspect exactly what commits are contained in this merge with the following:

`git log bad-merge...bad-merge~ --oneline`

Like so:

````
$ git log bad-merge...bad-merge~ --oneline
3996557 Fix conflcit lib/msf/util/exe.rb
6296c4f Merge pull request #9 from tabassassin/retab/pr/2320
d0a3ea6 Retab changes for PR #2320
bff7d0e Merge for retab
4c9e6a8 Default to exe-small
````

The syntax is a little wacky, but this is saying, "Show me all the commit hashes that occur from the `bad-merge` point to one back from `bad-merge` (iow, from right before `bad-merge` was merged). That's what the tilde (~) means. You could also use `bad-merge^` or `bad-merge^1`, they're all equivalent.

You can see the diff with the following command. Note the reverse placement of the `bad-merge` and `bad-merge~` commit points!

`git diff bad-merge~ bad-merge`

Take a look at that, confirm that yes, this is exactly what you want to revert, and then pull the trigger.

### Revert the merge

`git revert -m 1 bad-merge`

The `-m 1` bit is important, because that specifies that you want the branch to return to the point from before the merge -- I have never had reason to revert a merge and throw out the other side of the merge, but I imagine it comes up often enough for other people to not have it be the default behavior.

Note that this does /not/ reach into the repo and change history; for that, you would need to git push --force, and you [never want to do that on the master branch](www.reddit.com/r/programming/comments/1qefox/jenkins_developers_accidentally_do_git_push_force/). Instead, you are generating a new commit that reverses the contents of the merge commit. As usual, you will want to edit the commit message to be meaningful -- mention the affected commit hash and the affected pull request.

You will also want to `git commit -S --amend` after this to sign the commit; `git revert` does not take a `-S` option. Bummer.

### Create a new PR.

You will now create a new PR with your revert commit. That's simple enough. Again, be sure that the affected PRs are also informed; they may think their material landed, and while it technically did, it's no longer there; they will need to open new PRs and figure out how to resubmit their changes (hopefully, this time without causing merge conflicts).

### Bug the committers until your revert lands.

Until your revert commit lands, master will remain broken, so dealing with this situation should be blocking basically anything else. Be vocal.

## That's it!

If you have suggestions for fixes on this page, please bother [@todb-r7](https://github.com/todb-r7) with them.
