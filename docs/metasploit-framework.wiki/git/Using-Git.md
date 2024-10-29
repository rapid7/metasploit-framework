Use this collection of resources to work with the Metasploit Framework's git repository.

-------------

* [[Cheatsheet|Git cheatsheet]]
* [[Reference Sites|Git Reference Sites]]
* [[Setting Up a Metasploit Development Environment]] - this will walk you through creating a pull request
* [[Landing Pull Requests]] - this is the procedure that Metasploit core devs go through to merge your request
* [[Remote Branch Pruning]]

A fork is when you snapshot someone else's codebase into your own repo, presumably on github.com, and that codebase may have it's own branches, but you are usually snapshotting the master branch.  You usually then clone your fork to your local machine.  You then create your own branches, which are offshoots of your own fork.  Those snapshots, even if pushed to your github are not a part of the original codebase, in this case rapid7/metasploit-framework.  If you then submit a pull request, your branch (generally) can be pulled into the original codebase's master branch (usually... you could be pulled into an experimental branch or something if your code was a massive change or something, but that's not typical).

You only fork once, you clone as many times as you have machines on which you want to code, and you branch, commit, and push as often as you like (you don't always have to push, you can push later or not at all, but you'll have to push before doing a pull request, a.k.a. PR), and you submit a PR when you are ready.  See below

```plaintext
github.com/rapid7/metasploit-framework --> fork --> github.com/<...>/metasploit-framework
    ^                                                          |
    |                               git clone git://github.com/<...>/metasploit-framework.git
    |                                                          |
    `-- accepted <-- pull request                              V
                      ^                        /home/<...>/repo/metasploit-framework
                      |                                |              |          |
   github.com/<...>/metasploit-framework/branch_xyz    |              |          |
                      |                                |              V          V
                      |                                V           branch_abc   ...
                      `--       push       <--      branch_xyz
```

(Thanks to kernelsmith for this excellent description)
