Using **two-space soft tabs**, and not hard tabs, is the second precept<sup>*</sup> of the [Ruby Style Guide](https://github.com/bbatsov/ruby-style-guide#source-code-layout). This convention is widely adopted by nearly all Ruby projects, with Metasploit as of August of 2013 being the only major exception that we can think of.

We are looking to change this.

While we expect a fair amount of code conflict during the transition, we will have in place tools and procedures to quickly unconflict new submissions that prefer the current (old) style of hard tabs -- for the timeline to implementation, see below. By the end of 2013, the Metasploit Framework (and related projects) should be consistent with the rest of the Ruby world.

**TL;dr**: Please pardon our dust as we renovate Metasploit for your convenience.

This page can be found by the shortlink http://r-7.co/MSF-TABS

 <sup>*The first precept is UTF-8 encoding for source files, but we're going to keep ignoring that one for now since it monkeys with regexing over binary strings, which we do a lot. :)</sup>

## Retabbing outstanding pull requests.

Once metasploit-framework/master is retabbed, it's quite likely that several outstanding branches will be conflicted. The easiest way to solve these conflicts is for branch owners to reformat their own changed files with soft tabs (which should immediately unconflict). In order to ease the pain, the [@tabassassin](https://github.com/tabassassin) account will fire off a boiler plate PR back to outstanding branch maintainers who are affected with instructions on how to retab as well as actual retab commits they can land.

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
 - Offer retabbing to outstanding pull requests in the form of outbound PRs from [@tabassassin](https://github.com/tabassassin).
    * [This pull request](https://github.com/dmaloney-r7/metasploit-framework/pull/8) is an example of a one-off retab PR.

### By September 6, 2013
  - Announce the coming retabbing rumpus on the Metasploit blog.
  - Land the [retabbed branch]((https://github.com/tabassassin/metasploit-framework/compare/rapid7:master...retab;rumpus?expand=1)

### By September 18, 2013
 - Periodically retab as [@tabassassin](https://github.com/tabassassin) to catch stragglers that snuck in.
 - Periodically offer retabbing services as [@tabassassin](https://github.com/tabassassin) as above.
 - Write a procedure for retabbing incoming pull requests upon landing, per committer (don't bother with blocking on [@tabassassin](https://github.com/tabassassin) doing the work).

### By October 8
 - Convert msftidy.rb to enforce spaces only, warn about hard tabs.
 - Prepare for the onslaught of new code from experienced Ruby software devs who are no longer offended by our hard tabs.

## Changes or comments

Please bug [@todb-r7](https://github.com/todb-r7) if you have questions, or especially if you notice gaps in this plan. For example, I see right now there's no specific callout for rspec verification of spaces vs tabs, and that should run on at least a sample of modules and libraries as part of the retabbing exercise.