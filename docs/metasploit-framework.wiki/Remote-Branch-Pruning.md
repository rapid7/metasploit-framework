Since we have a lot of people creating and merging branches on the Metasploit GitHub repository, we need to periodically get rid of old and abandoned branches. Here's my technique:

# Back up the repo

Clone a new metasploit-framework.git repository:

`todb@presto:~/github/todb-r7$ git clone github_r7:rapid7/metasploit-framework.git msf-backup.git`

Go there and check out every remote branch we've got. That way, if you screw up and delete something important, you can add it back in later from this backup clone.

```
todb@presto:~/github/todb-r7$ cd msf-backup.git
`todb@presto:~/github/todb-r7/metasploit-framework$ for b in `git branch -r | grep -v "HEAD -> origin" | sed 's/^  origin\///'`; do git checkout -b $b --track origin/$b; done
```

Tarball it out of the way.

```
todb@presto:~/github/todb-r7$ cd ..
todb@presto:~/github$ tar zxvf msf-backup.git.tar.gz
todb@presto:~/github$ rm -rf msf-backup.git
```

# Make a new clone

Now, clone metasploit again. I do this because I have like 20 remotes to deal with on my "real" clone and I don't want to have to grep through all my origin vs non-origin stuff.

`mazikeen:./rapid7$ git clone github_r7:rapid7/metasploit-framework.git msf-prune`

Now start figuring out what branches to delete.

First, wipe out anything that responds to prune. Usually that's not a lot.

`mazikeen:./msf-prune$ git prune remote origin`

Next, take a look at what's already merged and what's not. We can drop most of the merged stuff right away.

```
mazikeen:./msf-prune$ git branch -r --merged 
mazikeen:./msf-prune$ git branch -r --no-merged 
```

That gives a pretty good idea of how many branches we're talking about.

# Start deleting old, merged branches

Here's a one-liner, lightly modified from http://stackoverflow.com/questions/2514172/listing-each-branch-and-its-last-revisions-date-in-git#2514279 which lists all remote **merged** branches in date order.

```
mazikeen:./msf-prune$ for k in `git branch -r --merged |grep -v "HEAD ->" | sed s/^..//`; do echo -e `git log -1 --pretty=format:"%Cgreen%ci %Cblue%cr%Creset" $k --`\\t"$k";done | sort
```

Count off how many you want to keep at the end, do the arithmetic, and tack on another couple pipes to catch everything that's more than two weeks old. These are the merged branches that nobody's likely to miss.

```
mazikeen:./msf-prune$ for k in `git branch -r --merged |grep -v "HEAD ->" | sed s/^..//`; do echo -e `git log -1 --pretty=format:"%Cgreen%ci %Cblue%cr%Creset" $k --`\\t"$k";done | sort | head -45 | sed "s/^.*origin\///" > /tmp/merged_to_delete.txt
```

Pull the trigger:

```
mazikeen:./msf-prune$ for b in `cat /tmp/merged_to_delete.txt`; do echo Deleting $b && git push origin :$b; done
```

Note that we still have our tarball, so if we need to reinstate any of these branches, just need to re-push.

# Repeat for the unmerged branches

Pretty much the same as above, but use `--no-merged` instead of `--merged` and allow for older unmerged branches (say, 2 months).

# Tell people about it.

Sometimes, some people may run into sync problems with these missing branches and need to `git remote prune origin` themselves. Alternatively, they want to look into these branches again -- especially the unmerged ones. So, let people know that you just did this on the metasploit-hackers list and the Freenode IRC channel. If someone wants an old branch back, just go to your backup clone and push it back up as you would any branch: `git checkout branchname && git push origin branchname`. No problem.

