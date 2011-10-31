#Git Cheatsheet

Here is a set of some of the most common things you'll need to do in
your day-to-day workflow with Git.

## Fetch, Pull, and Push

* Get all new changes, and remote branch refs

    `git fetch`

* Do a git fetch and (if possible) a merge on the current branch

    `git pull`

* Push commits to to the origin/master (like an SVN commit):

    `git push origin master`

* Push commits on a non-master branch:

    `git push origin/your_branch_name`

## Branching

* See a list of local branches

    `git branch`

* Switch to an existing branch

    `git checkout existing_branch_name`

* Create a new branch and switch to it:

    `git checkout -b new_branch_name`


## Merging, Rebasing, and Stashing

* Merge my working branch into master (from master):
    
    `git merge working_branch_name`

* Merge a large set of commits on a dev branch into master as one
  commit ("squash" commit):

    `git merge working_branch_name --squash`

* Get the changes that have happened to master branch since I made my
  working branch:

    `git rebase master`

* Temporarily clear my stage so I can switch to another branch
  ("stashing"):

    `git stash`

* Get my stashed stuff back:

    `git stash apply`

## History, Conflicts, and Fixing Mistakes

* See the log of commits:

    `git log`

* See what changes were made in a given commit:

    `git show COMMIT_HASH`

* See more detailed log information:

    `git whatchanged`

* Get rid of all the changes I've made since last commit:
    
    `git reset --hard`

* Get rid of the changes for just one file:

    `git checkout FILENAME`

* Make HEAD point to the state of the codebase as of 2 commits ago:

    `git checkout HEAD^^`

* Fix a conflict (w/ system's default graphical diff tool):

    `git mergetool`


