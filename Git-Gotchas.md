If you've created a topic branch on your personal fork as described in [[Metasploit Development Environment]], rebasing from upstream/master is a little tricky.  This link explains what can go wrong:  http://blog.evan.pro/a-simple-explanation-of-git-rebase

Basically, rebasing will put you into a state where you have a local commit with a different sha1 from your remote commit of the same patch.  So don't do that.  Instead, use ```git merge upstream/master``` if you need to pull in new commits from rapid7's fork.  But!  As @tpope explains, it may not be worth the clogged up history, so don't do that either.  http://tbaggery.com/2008/04/18/example-git-workflows-maintaining-a-long-lived-topic-branch.html

