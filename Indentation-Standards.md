Using **two-space soft tabs**, and not hard tabs, is the second precept<sup>*</sup> of the [Ruby Style Guide](https://github.com/bbatsov/ruby-style-guide#source-code-layout). This convention is widely adopted by nearly all Ruby projects, with Metasploit as of August of 2013 being the only major exception that we can think of.

We are looking to change this.

While we expect a fair amount of code conflict during the transition, we will have in place tools and procedures to quickly unconflict new submissions that prefer the current (old) style of hard tabs -- for the timeline to implementation, see below. By the end of 2013, the Metasploit Framework (and related projects) should be consistent with the rest of the Ruby world.

**TL;dr**: Please pardon our dust as we renovate Metasploit for your convenience.

This page can be found by the shortlink http://r-7.co/MSF-TABS

 <sup>*The first precept is UTF-8 encoding for source files, but we're going to keep ignoring that one for now since it monkeys with regexing over binary strings, which we do a lot. :)</sup>

## Retabbing outstanding pull requests.

Once metasploit-framework/master is retabbed, it's quite likely that several outstanding branches will be conflicted. The easiest way to solve these conflicts is for branch owners to reformat their own changed files with soft tabs (which should immediately unconflict). In order to ease the pain, the [@tabassassin](https://github.com/tabassassin) account will fire off a boiler plate PR back to outstanding branch maintainers who are affected with instructions on how to retab as well as actual retab commits they can land.

### Retabbing on your own

Retabbing your own feature branch to un-conflict your changes is pretty easy. Follow this procedure, which assumes that you have Rapid7's repo named "upstream" (as recommended in the [MSF developer guide](https://github.com/rapid7/metasploit-framework/wiki/Setting-Up-a-Metasploit-Development-Environment#check-out-the-upstream-master-branch).


````
git fetch upstream
git merge upstream/master -m "Merge for retab" -s recursive -X ours
````

This will merge in the upstream/master branch into your branch, preferring YOUR changes to all conflicting files. This will ensure that your changes are preserved.

````
./tools/dev/retab.rb lib/
./tools/dev/retab.rb modules/
````

This will apply the new space intendation to your changes in `lib/` and `modules/`. If you only have changes in one of these directories, just pick that one. (Just so you know, we're not retabbing `data` or the top-level scripts quite yet, since we want to get through the hardest bit first).

````
git diff -w HEAD
`````

This diffs your local branch with the state just prior to retabbing, ignoring whitespace changes. It should return nothing, indicating that there has been no content change. This is good.

````
git commit -a -m "Retab changes for PR #1234"
````

This commits the retabbing changes. Substitute `#1234` for your own PR number, of course.

````
git push origin your-branch-name
````

This will push the results up to your remote branch (substitute `your-branch-name` of course). This will automatically update your pull request with two new commits, the merge and the retab.

### TL;DR on retabbing:

If you're feeling charitable, you can do this to someone else's PR as well.

````
git checkout -b retab/pr/XXXX --track upstream/pr/XXXX
git merge master -m "Merge for retab" -s recursive -X ours
tools/dev/retab.rb lib/ && tools/dev/retab.rb modules/
git diff -w HEAD # Ensure all is copacetic.
git commit -a -m "Retab changes for PR #XXXX"
git push origin
git pr-url contributor-username contributor-branch
````

Note that `pr-url` is a custom alias in my .git/config:

````
[alias]
  pr-url =!"xdg-open https://github.com/YOURUSERNAME/metasploit-framework/pull/new/$1:$2...$(git branch-current) #"
````
It's hella useful.

## Implementation Timeline

Items struck out are complete.

### By August 15, 2013
 - ~~Add a retabbing utility~~
 - ~~Update msftidy.rb to respect spaces or tabs, but not mixed.~~
 - ~~Add a test case~~
 - ~~Land [PR #2197](https://github.com/rapid7/metasploit-framework/pull/2197) which provides the above.~~
 - ~~Ask CoreLan (sinn3r) to update mona.py templates to use spaces, not tabs.~~
 - ~~Verify [mona.py](http://redmine.corelan.be/projects/mona) is updated.~~

Note that once [PR #2197](https://github.com/rapid7/metasploit-framework/pull/2197) lands, we will no longer be enforcing any particular tab/space indentation format until about October 8, when we switch for real to soft tabs.

### By ~~August 28, 2013~~ September 3, 2013

By now, we should have a pretty good idea of how to deal with conflicts and how to ensure everyone has a pretty painless path to fix up their own branches with the new retabbing. In fact, [PacketFu's PR #33](https://github.com/todb/packetfu/pull/33) is an example of this in action.

 - ~~Write a procedure for offering retabbing to outstanding pull requests.~~
 - ~~Retab modules directory as [@tabassassin](https://github.com/tabassassin) using `retab.rb`~~
 - ~~Retab libraries as [@tabassassin](https://github.com/tabassassin) using `retab.rb`.~~
    * See the [retab/rumpus](https://github.com/tabassassin/metasploit-framework/compare/rapid7:master...retab;rumpus?expand=1) branch.
 - ~~Offer retabbing to outstanding pull requests in the form of outbound PRs from [@tabassassin](https://github.com/tabassassin).~~
    * The pull requests that were outstanding at the time of the retabbing are recorded [in this gist](https://gist.github.com/todb-r7/6456477), indicating which were conflicting and which were not.
    * [This pull request](https://github.com/rapid7/metasploit-framework/pull/2325) is an example of an outstanding PR that was successfully retabbed with [this retabbing PR](https://github.com/jlee-r7/metasploit-framework/pull/5)

### By September 6, 2013
  - ~~Announce the coming retabbing rumpus on the Metasploit blog.~~
    * This happened [on the Metasploit update blog post](https://community.rapid7.com/community/metasploit/blog/2013/09/05/weekly-update).
  - ~~Land the [retabbed branch]((https://github.com/tabassassin/metasploit-framework/compare/rapid7:master...retab;rumpus?expand=1)~~
    * Landed as [PR #2330](https://github.com/rapid7/metasploit-framework/pull/2330)

### By September 13, 2013
  - Retab spec, top-level, and everything else Ruby.
  - Run through outstanding PRs again, looking for conflicts.

### By September 18, 2013
 - Periodically retab as [@tabassassin](https://github.com/tabassassin) to catch stragglers that snuck in.
 - Periodically offer retabbing services as [@tabassassin](https://github.com/tabassassin) as above.
 - ~~Write a procedure for retabbing incoming pull requests upon landing, per committer (don't bother with blocking on [@tabassassin](https://github.com/tabassassin) doing the work).~~
  * Right here in [MSF-TABS](https://github.com/rapid7/metasploit-framework/wiki/Indentation-Standards#tldr-on-retabbing)

### By October 8
 - Convert msftidy.rb to enforce spaces only, warn about hard tabs.
 - Prepare for the onslaught of new code from experienced Ruby software devs who are no longer offended by our hard tabs.

## Changes or comments

Please bug [@todb-r7](https://github.com/todb-r7) if you have questions, or especially if you notice gaps in this plan. For example, I see right now there's no specific callout for rspec verification of spaces vs tabs, and that should run on at least a sample of modules and libraries as part of the retabbing exercise.