The process of incorporating a downstream change back into the framework is known as "landing" a pull request. To get started, we need to check out the pull request page.

[[pull-request.png]]

## Create remote

If anything looks awry in the diff, we can leave a comment on the pull request to suggest changes from the user. We can also see the name of the remote branch that we'll want to pull down, assuming everything looks good. We'll start by creating a remote for the requesting user:

```console
$ git remote add swtornio git://github.com/swtornio/metasploit-framework.git
```

Making the remote name match the user's name keeps things simple. 

## Create tracking branch

Now we'll create a branch that tracks the remote branch listed in the pull request, in this case, `master`:

```console
$ git fetch swtornio
remote: Counting objects: 38, done.
remote: Compressing objects: 100% (12/12), done.
remote: Total 21 (delta 18), reused 12 (delta 9)
Unpacking objects: 100% (21/21), done.
From git://github.com/swtornio/metasploit-framework
 * [new branch]      master     -> swtornio/master
$ git branch --track swtornio swtornio/master
Branch swtornio set up to track remote branch master from swtornio.
```

## Rebase and review changes

Now we'll want to inspect the changes that have been pulled down. We'll start by checking out the branch we just created:

```console
$ git checkout swtornio
Switched to branch 'swtornio'
```

Now we'll rebase the changes against the master branch. This allows us to get any merge conflicts out of the way:

```console
$ git rebase master
First, rewinding head to replay your work on top of it...
Applying: fixed in osvdb
Applying: add osvdb ref
```

Finally, review the diff with `git diff master`:

```diff
diff --git a/modules/exploits/multi/browser/java_rhino.rb b/modules/exploits/multi/browser/java_rhino.rb
index a6352d4..15404e4 100644
--- a/modules/exploits/multi/browser/java_rhino.rb
+++ b/modules/exploits/multi/browser/java_rhino.rb
@@ -34,7 +34,7 @@ class Metasploit3 < Msf::Exploit::Remote
                        'References'    =>
                                [
                                        [ 'CVE', '2011-3544' ],
-                                       [ 'OSVDB', '76500' ], # 76500 and 76499 have contents mixed
+                                       [ 'OSVDB', '76500' ],
                                        [ 'URL', 'http://www.zerodayinitiative.com/advisories/ZDI-11-305/' ],
                                        [ 'URL', 'http://schierlm.users.sourceforge.net/CVE-2011-3544.html' ],
                                ],
diff --git a/modules/exploits/windows/ftp/servu_chmod.rb b/modules/exploits/windows/ftp/servu_chmod.rb
index 7bba0e4..d341d41 100644
--- a/modules/exploits/windows/ftp/servu_chmod.rb
+++ b/modules/exploits/windows/ftp/servu_chmod.rb
@@ -33,6 +33,7 @@ class Metasploit3 < Msf::Exploit::Remote
                        'References'     =>
                                [
                                        [ 'CVE', '2004-2111'],
+                                       [ 'OSVDB', '3713'],
                                        [ 'BID', '9483'],
                                ],
                        'Privileged'     => true,
```

## Merge to master and push

Assuming everything looks good, we can hop back over to the master branch and squash-merge these changes. First, we'll want to grab the original author's info by inspecting the `git log`:

```
commit 0b109da71e4c8ce81894cb6e0020d20c0d4eb66c
Author: Steve Tornio <swtornio@gmail.com>
Date:   Fri Dec 2 07:44:28 2011 -0600

    add osvdb ref
```

We'll need to grab everything listed in the `author` line into our clipboard. Now, checkout `master` and perform the squash merge:

```console
$ git checkout master
Switched to branch 'master'
Your branch is behind 'origin/master' by 11 commits, and can be fast-forwarded.
$ git merge --squash swtornio
Updating 424901b..0b109da
Fast-forward
Squash commit -- not updating HEAD
 modules/exploits/multi/browser/java_rhino.rb |    2 +-
 modules/exploits/windows/ftp/servu_chmod.rb  |    1 +
 2 files changed, 2 insertions(+), 1 deletions(-)
```

This has staged all of the changes from that branch, but hasn't committed anything, yet. Now we'll run the following:

```console
$ git commit --author="Steve Tornio <swtornio@gmail.com>"
```

I've pasted in the author info from earlier to the `--author` option. This will ensure that @swtornio gets credit for his work, while we are listed as the committer. Not specifying the commit message will open up a new commit message for us in an editor:

```
Update OSVDF refs for servu module.
* Added osvdb ref to servu module.
* Fixed rhino entry in osvdb, removed comment from module.

Squashed commit of the following:

commit 80ce652
Author: Steve Tornio <swtornio@gmail.com>
Date:   Fri Dec 2 07:44:28 2011 -0600

    add osvdb ref

commit 558f20d
Author: Steve Tornio <swtornio@gmail.com>
Date:   Wed Nov 30 08:15:20 2011 -0600

    fixed in osvdb

[Fixes #4567][Closes #39]
```

Here, I've followed [the git commit message style espoused by Tim Pope](http://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html). Note the line at the bottom. By specifying a `Fixes` section for each Redmine issue, and a `Closes` section for the pull request number (which can be found in the URL of the pull request page), we can close both the issue and the request with this commit message. Save the file and push up the commit, and now the pull request page will show a status of 'Closed' with a link to your commit:

[[closed-pull-request.png]]



