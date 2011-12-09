So you've been gleefully creating topic branches, creating pull
requests, and having them accepted into the framework. Now what should
you do about all of those pesky remote branches that are still hanging
around?

First, check to see which remote branches currently exist on your
remote:

```console
$ git fetch
remote: Counting objects: 48, done.
remote: Compressing objects: 100% (29/29), done.
remote: Total 37 (delta 28), reused 17 (delta 8)
Unpacking objects: 100% (37/37), done.
From github-r7:rapid7/metasploit-framework
   b7ccbcd..e043fb5  master     -> origin/master
   0b4a282..499a1f1  rails3     -> origin/rails3
 * [new tag]         20111205000001 -> 20111205000001
$ git branch -r
  origin/5306-vxworks-memory-dump
  origin/HEAD -> origin/master
  origin/fastlib
  origin/feature/1234-some-feature
  origin/iss5979
  origin/issue_3386_cisco
  origin/master
  origin/rails3
  origin/release/20111205000001
  origin/servu_sploit
  origin/stable
  scriptjunkie/(u)efi_pxe
  scriptjunkie/badcharsgui
  scriptjunkie/master
  scriptjunkie/multithread
```

Once you know which branch you'd like to delete, use the following
(somewhat funky) syntax:

```console
$ git push origin :feature/1234-some-feature
To git@github.com:rapid7/metasploit-framework.git
 - [deleted]         feature/1234-some-feature
```
