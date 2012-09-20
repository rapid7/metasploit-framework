# Metasploit Bug Reporting

As any open source software grows in popularity, there is a tendency to see an increase in bug report volume against that software coupled with a corresponding decrease in bug report quality. We are not against getting bug reports for Metasploit -- we need bug reports in order to know what's broken. So, rather than trying to stem the tide of bugs, this page will attempt to make sure that each bug report we get is written in a way that maximizes its chances of actually getting resolved.

That said, there are two situations where you generally oughtn't open a bug at all, and that's when you have a support contract, or when you've found a security issue with Metasploit itself.

# Support Contracts

If you have a support contract for a Metasploit product, you ought to get in touch with your Rapid7 support representative, or write to support@rapid7.com. The people who work Metasploit support full time are really pretty with-it are likely to have a fix or a workaround for you on the spot.

# Security Issues

If you have a security issue with Metasploit itself, then we'd really appreciate it if you let us know at security@metasploit.com. After all,  we'd like to [be treated as we treat other software projects](http://www.rapid7.com/disclosure.jsp). It's not because we'd like to bury your bug -- we'd just like to have a shot at fixing your bug before someone starts messing with our innocent users. We're happy to give you credit, keep you anonymous, inform you about progress, and explore related issues with you -- but if we see someone reporting security bugs out in public, then it gets a lot harder to keep all that attribution and communication straight as we try not to break our necks implementing a fix as fast as we can.

Also, if you could report your security bug in the form of a Metasploit module sent to security@metasploit.com, that would be both ideal and hilarious.

That should cover the cases where you shouldn't open a bug at all, so let's move on to our main issue tracking system, Redmine.

# Redmine

The final destination for bug reports in Metasploit is our Redmine [issue tracker](https://dev.metasploit.com/redmine/projects/framework/issues?set_filter=1). In order to file bug reports, you must first [create an account](https://dev.metasploit.com/redmine/account/register). Sadly, we can't take anonymous bug reports at this time due to spam, but we are actively exploring ways to make the registration as painless as possible.

In conversation about Metasploit and someone asks, "is there a bug?" or refers to "the bug tracker" or "Redmine," we're nearly always talking about this system.

# Avoiding Duplicates

You may not be the first person to notice the problem you're running into, so here are some strategies for ensuring that a previously reported bug gets attention.

If you're having a problem with a particular module, you might try [searching that module's name](https://dev.metasploit.com/redmine/projects/framework/search?issues=1&q=ie_execcommand_uaf) to see if there's anything already reported. If your bug has a particular error message, [look for that](https://dev.metasploit.com/redmine/projects/framework/search?utf8=%E2%9C%93&q=%22nomethoderror+undefined+method%22+empty&scope=&all_words=&all_words=1&titles_only=&issues=1&submit=Submit).

Another tactic is to simply glance at [the most recent](https://dev.metasploit.com/redmine/projects/framework/issues?set_filter=1&f%5B%5D=status_id&op%5Bstatus_id%5D=o&f%5B%5D=created_on&op%5Bcreated_on%5D=>t-&v%5Bcreated_on%5D%5B%5D=5&f%5B%5D=&c%5B%5D=tracker&c%5B%5D=parent&c%5B%5D=status&c%5B%5D=priority&c%5B%5D=subject&c%5B%5D=assigned_to&c%5B%5D=updated_on&c%5B%5D=category&group_by=) bugs, especially if you suspect this a new bug in a process you're sure used to work before.

If you happen to find the bug you're experiencing, updating that report with any new information is hugely helpful in coming to a resolution. You might also find resolved bugs that describe your problem, which indicates a regression (old bugs reintroduced) -- the fixes for those are usually fast, so noting likely regressions is quite useful.

Finally, you might find a bug that's been rejected or closed. In these cases, the problem is usually something external to Metasploit -- user error, configuration weirdness, known incompatibilities, etc. If you think that the original resolution was in error, though, open a new bug and point out what you think the problem is. After all, if people keep running into the same non-bug, then it's probably at least a documentation bug, and maybe something real.

# Describing your bug

## Make your bug findable

Since we talk a lot about the importance of finding dupes before submitting, make sure that your bug is findable. Use specific module names and error messages in the title, and include as much of the error as you can in the report. "The Windows login aux mod is broken" is a terrible title, while "NoMethodError raised on smb_login module" is much better. 

Check out [Bug #6905](https://dev.metasploit.com/redmine/issues/6905). If all our bug reports looked like this, I'd be delighted. It's pretty short, and has the all basics -- a short but descriptive title, a full backtrace of the error, a complete history of how he got there, and version information. This bug is very search-friendly, as well as easy to reproduce.

## Reproducing your bug

Sometimes, though, your bug is trickier to reproduce.


# Submitting Patches

# Following your bug