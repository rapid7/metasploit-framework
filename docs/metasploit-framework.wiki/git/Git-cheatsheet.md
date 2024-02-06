## Git Cheatsheet (survival level)

Here is a set of some of the most common things you'll need to do in
your day-to-day workflow with Git.

**Pro Tip 1:** you can get man pages for any git command by inserting a hyphen.  As in: "man git-fetch" or "man git-merge"

**Pro Tip 2:** install the [cheat gem](http://cheat.errtheblog.com/) for a really long cheat sheet available in your terminal.

## What's going on?

* What branch am I on? Which files are modified, which are staged, which are untracked, etc?

    `git status`

## Fetch, Pull, and Push

* Get all new changes, and remote branch refs

    `git fetch`

* Do a git fetch and (if possible) a merge on the current branch

    `git pull`

* Push commits to the origin/master (like an SVN commit):

    `git push origin master`

* Push commits on a non-master branch:

    `git push origin your_branch_name`

## Branching

* See a list of local branches

    `git branch`

* Switch to an existing branch

    `git checkout existing_branch_name`

* Create a new branch and switch to it:

    `git checkout -b new_branch_name`


## Merging and Stashing

* Merge my working branch into current branch:
    
    `git merge working_branch_name`

* Temporarily clear my stage so I can switch to another branch
  ("stashing"):

    `git stash`

* Get my stashed stuff back, leaving it in the list of stashes:

    `git stash apply`

* Get my stashed stuff back, removing it from the list:

    `git stash pop`

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

* Revert a commit (be careful with merges!):

    `git revert <commit hash>`

* Revert a commit from a merge:

    `git revert -m<number of commits back in the merge to revert> <hash of merge commit>`
     
(e.g. git revert -m1 4f76f3bbb83ffe4de74a849ad9f68707e3568e16 will revert the first commit back
     in the merge performed at 4f76f3bbb83ffe4de74a849ad9f68707e3568e16)


## Git in Bash
When using Git, it's very handy (read: pretty much mandatory) to have an ambient cue in your shell telling you what branch you're currently on.  Use this function in your .profile/.bashrc/.bash_profile to enable you to place your Git branch in your prompt:

```sh
function parse_git_branch {
  git branch --no-color 2> /dev/null | sed -e '/^[^*]/d' -e 's/* \(.*\)/(\1)/'
}
```
