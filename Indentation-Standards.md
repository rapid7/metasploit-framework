Using **two-space soft tabs**, and not hard tabs, is the second precept<sup>*</sup> of the [Ruby Style Guide](https://github.com/bbatsov/ruby-style-guide#source-code-layout). This convention is widely adopted by nearly all Ruby projects, with Metasploit as of August of 2013 being the only exception that we can think of.

We are looking to change this.

More details on the timeline and practical effects of switching over to spaces instead of tabs will be coming soon on this wiki page. The short story is, while we expect a fair amount of code conflict during the transition, we will have in place tools and procedures to quickly unconflict new submissions that prefer the current (old) style of hard tabs. By the end of 2013, the Metasploit Framework (and related projects) should be consistent with the rest of the Ruby world.

IOW, please pardon our dust as we renovate Metasploit for your convenience.

 <sup>*The first precept is UTF-8 encoding for source files, but we're going to keep ignoring that one for now since it monkeys with regexing over binary strings, which we do a lot. :)</sup>

## Change Timeline

### By August 15, 2013
 - Add a retabbing utility
 - Update msftidy.rb to respect spaces or tabs, but not mixed.
 - Add a test case
 - Ask CoreLan to update mona.py templating to use spaces, not tabs.
 - Verify mona.py's update.

Note that once msftidy.rb lands, we will no longer be enforcing any particular tab/space indentation format.

### By August 28, 2013
 - Write a procedure for offering retabbing to outstanding pull requests.
 - Retab modules directory as @tabassassin using `retab.rb`
 - Retab libraries as @tabassassin using `retab.rb`.
 - Offer retabbing to outstanding pull requests in the form of outbound PRs from @tabasssassin.

### By September 18, 2013
 - Periodically retab as @tabassassin to catch stragglers that snuck in.
 - Periodically offer retabbing services as @tabassassin as above.
 - Write a procedure for retabbing incoming pull requests upon landing, per committer (don't bother with blocking on @tabassassin doing the work).

### By October 8
 - Convert msftidy.rb to enforce spaces only, warn about hard tabs.
 - Prepare for the onslaught of new code from experienced Ruby software devs who are no longer offended by our hard tabs.