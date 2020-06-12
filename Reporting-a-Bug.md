# Metasploit Bug Reporting

As any open source software product grows in popularity, there is a tendency to see an **increase** in bug report volume coupled with a corresponding **decrease** in bug report quality. We are not against getting bug reports for Metasploit -- we need bug reports in order to know what's broken. So, rather than trying to stem the tide of bugs, this page will attempt to make sure that each bug report we get is written in a way that maximizes its chances of actually getting resolved.

By this point, the Metasploit development community has read thousands of bug reports, and it turns out, well-written bug reports tend to make fixing those bugs much faster and easier. It's really pretty remarkable that a speedy time-to-close seems to corellate so strongly with bug report quality and not the  complexity of the bug itself.

That said, there are two situations where you generally oughtn't open a bug at all, and that's when you have a support contract, or when you've found a security issue with Metasploit itself.

## Support Contracts

If you have a support contract for a Metasploit product, you ought to get in touch with your Rapid7 support representative, or write to support@rapid7.com. The people who work Metasploit support full time are really pretty with-it are likely to have a fix or a workaround for you on the spot.

## Security Issues

If you have a security issue with Metasploit itself, then we'd really appreciate it if you let us know at security@metasploit.com. After all,  we'd like to [be treated as we treat other software projects](http://www.rapid7.com/disclosure.jsp). It's not because we'd like to bury your bug -- we'd just like to have a shot at fixing your bug before someone starts messing with our innocent users. We're happy to give you credit, keep you anonymous, inform you about progress, and explore related issues with you -- but if we see someone reporting security bugs out in public, then it gets a lot harder to keep all that attribution and communication straight as we try not to break our necks implementing a fix as fast as we can.

Also, if you could report your security bug in the form of a Metasploit module sent to security@metasploit.com, that would be both ideal and hilarious.

That should cover the cases where you shouldn't open a bug at all, so let's move on to our main issue tracking system, Redmine.

# Introducing Redmine

The final destination for bug reports in Metasploit is our Redmine [issue tracker](https://dev.metasploit.com/redmine/projects/framework/issues?set_filter=1). This is where all issues that we want to track are born, grow old, and eventually die.

In order to file bug reports, you must first [create an account](https://dev.metasploit.com/redmine/account/register). It's easy and fun. Sadly, we can't take truly anonymous bug reports at this time due to spambots, but we are actively exploring ways to make this registration as painless and easy for humans as we can.

In conversation about Metasploit and someone asks, "is there a bug?" or refers to "the bug tracker" or "Redmine," we're nearly always talking about this system.

## They're all Bugs

Speaking of conversation, it's important to note that we will tend to refer to all issues as "bugs," regardless if it's actually a defect, a feature request, a or a support request. It's just fewer syllables and characters, and is not meant to disparage the content of the issue.

## GitHub Issues

We have an [Issue Tracker](https://github.com/rapid7/metasploit-framework/issues) enabled on the GitHub repo, but, as mentioned above, bugs should hit Redmine if they're going to be tracked. We had a fantasy of closing down Redmine for a while there and switching over to GitHub Issues completely, but Redmine is still just too useful to abandon.

So, in the interim, nobody is going to stop you from filing GitHub issues. Many GitHub projects have an "Issues" button, and we'd rather not surprise people and make them dig through the wiki to figure out how to report bugs. If you're reading this, you're now enlightened, so should avoid that Issues tab.

## E-mail

We maintain a couple mailing lists -- the [Metasploit Framework](http://mail.metasploit.com/mailman/listinfo/framework) and the [Metasploit-Hackers](https://lists.sourceforge.net/lists/listinfo/metasploit-hackers) lists. Sometimes people will run into problems and they'll mention them there. Sometimes, someone will put together bug reports based on traffic on these lists, but sometimes nobody will. The point is, if you're not sure if you have a bug or just a question on usage, start off with an e-mail to the Framework list. If you're pretty sure you have a bug, it's probably best to start off with a regular ol' bug report, and maybe mention it afterwards on one of these lists.

## Rapid7 Community

Rapid7 runs a Metasploit user community over at (wait for it) [community.rapid7.com](https://community.rapid7.com/community/metasploit). Like e-mail, this is mostly a venue for discussion and help with using Metasploit, and not so much for bug reporting.

# Getting Started 

Enough talk, on to the mechanics of bug reporting!

## Avoiding Duplicates

You may not be the first person to notice the problem you're running into, so here are some strategies for ensuring that a previously reported bug gets attention.

If you're having a problem with a particular module, you might try [searching that module's name](https://dev.metasploit.com/redmine/projects/framework/search?issues=1&q=ie_execcommand_uaf) to see if there's anything already reported. If your bug has a particular error message, [look for that](https://dev.metasploit.com/redmine/projects/framework/search?utf8=%E2%9C%93&q=%22nomethoderror+undefined+method%22+empty&scope=&all_words=&all_words=1&titles_only=&issues=1&submit=Submit).

Another tactic is to simply glance at [the most recent](https://dev.metasploit.com/redmine/projects/framework/issues?set_filter=1&f%5B%5D=status_id&op%5Bstatus_id%5D=o&f%5B%5D=created_on&op%5Bcreated_on%5D=>t-&v%5Bcreated_on%5D%5B%5D=5&f%5B%5D=&c%5B%5D=tracker&c%5B%5D=parent&c%5B%5D=status&c%5B%5D=priority&c%5B%5D=subject&c%5B%5D=assigned_to&c%5B%5D=updated_on&c%5B%5D=category&group_by=) bugs, especially if you suspect this a new bug in a process you're sure used to work before.

If you happen to find the bug you're experiencing, updating that report with any new information is hugely helpful in coming to a resolution. You might also find resolved bugs that describe your problem, which indicates a regression (old bugs reintroduced) -- the fixes for those are usually fast, so noting likely regressions is quite useful.

Finally, you might find a bug that's been rejected or closed. In these cases, the problem is usually something external to Metasploit -- user error, configuration weirdness, known incompatibilities, etc. If you think that the original resolution was in error, though, open a new bug and point out what you think the problem is. After all, if people keep running into the same non-bug, then it's probably at least a documentation bug, and maybe something real.

# Describing your bug

## Make your bug searchable

Since we talk a lot about the importance of finding dupes before submitting, make sure that your bug is findable. Use specific module names and error messages in the title, and include as much of the error as you can in the report. "The Windows login aux mod is broken" is a terrible title, while "NoMethodError raised on smb_login module" is much better.

Most of the time, bugs you run into don't have nice, clean error messages. In these cases, try to pin down what you can in the title. For example, see [Bug #7215](https://dev.metasploit.com/redmine/issues/7215) -- this is a pretty typical complaint that some module is failing to open a shell, but notice that while the module name isn't in the title, it is in the opening description. Also, this bug has tons of logs and screen captures.

## Logs and screen captures

Check out [Bug #6905](https://dev.metasploit.com/redmine/issues/6905). If all our bug reports looked like this, I'd be delighted. It's pretty short, and has the all basics -- a short but descriptive title, a full backtrace of the error, a complete history of how he got there, and version information. This bug is very search-friendly, as well as easy to reproduce.

If you're testing a module in a lab or virtual environment, we'd love to get as much data about the target as you can provide. This means exact versions of the target including patch levels, pcaps if you can capture them, and any kind of logging inside or outside of Framework.

Often, we'll ask for the `framework.log` -- that's usually kept in `$HOME/.msf4/framework.log`.

On the other hand, if you run into an issue on an engagement, we understand that you can't include a bunch of client data in your bug report. In those cases, we will still bug you for logs, but you'll need to santize them first, and we won't have our feelings hurt if you need to refuse. Such is the business of penetration testing.

## Mention Your Environment

It may be that the bug you're describing only comes up in your environment. If you're not on the normal [Metasploit Development Environment](https://github.com/rapid7/metasploit-framework/wiki/Metasploit-Development-Environment) or the [Metasploit Installation](http://www.rapid7.com/downloads/metasploit.jsp) you will want to mention this specifically in your bug report. The output of the commands `ruby -v` , and  `uname -a` (or `winver`) is usually very helpful.

## Include steps to reproduce

At a minimum, the steps you took to get to your predictament are probably found in `$HOME/.msf4/history`, so you can cut and paste from there. If there's more background than what's contained in the command history, like funny network configurations that might be in play, then mention that, too.

We love resource scripts (rc scripts) that can be used to reliably trigger your bug. Those scripts can eventually find their way into repeatable test cases, so if you can put one together, great! For more on resource script writing, see [this blog post](https://community.rapid7.com/community/metasploit/blog/2010/03/22/automating-the-metasploit-console).

# Patches

## Providing Patches

Maybe you've run into a bug, and you already know how to fix it. Or, you're just a kind stranger on the Internet who wants to help out. The most reliable way to get your patches into Metasploit is to patch your own fork, and sling a [pull request](https://github.com/rapid7/metasploit-framework/wiki/Metasploit-Development-Environment#wiki-pull) our way. Since you're attacking a bug that already exists, you can use a special commit message string of either `[SeeRM #1234]` or `[FixRM #1234]` and that will update Redmine with a pointer to your commit automatically, once the fix is landed. Since it's human-readable, we can tell immediately that you're talking about a Redmine issue, as well, so you or someone can update Redmine with a link to your pull requestr.

Of course, this all presumes you're hooked into GitHub. If this doesn't work for you, you can attach patches to a Redmine issue by simply creating a patch diff against a recent checkout of Metasploit -- this is going to be the case for most SVN users (and in that case, you'll want to use `svn diff`).

Now, be forewarned: patches submitted directly to Redmine are more cumbersome to work with, especially if there are more questions. If you plan on patching more than once or twice, it would behoove you to take a little time to set up your [Metasploit Development Environment](https://github.com/rapid7/metasploit-framework/wiki/Metasploit-Development-Environment) and start playing along at home.

## Providing Test Cases

We like -- no, love -- to have tests that show that a patch actually works. Again, [Resource Scripts](https://community.rapid7.com/community/metasploit/blog/2010/03/22/automating-the-metasploit-console) are a great way to get something quick put together, and you can combine this with the standard utility `screen` for some excellent resolutions:

  * Fire up `screen` and hit `Ctrl-a H` (mind the caps)
  * `msfconsole -L -q -r /path/to/your/test.rc`
  * Exit msfconsole and `git checkout branch-containing-fix`
  * `msfconsole -L -q -r /path/to/your/test.rc`
  * `exit` to leave screen

This will generate a screen log of your fix that includes all your output and all your keystrokes. Yes, it'll look horrible in a regular text editor due to the various escape codes, but `cat` and `less` are both more than adequate to resolve those.

If you're on Windows, the msfconsole `spool` command should provide enough output to at least demo the problem and its solution.

# Following bugs

So, you go to all the effort of filing a bug, and you want to make sure it gets resolved. What next?

## Notification settings

If you opened a bug on Redmine, you should automatically be getting updates to it via e-mail, and the same goes for GitHub pull requests. If you're not for some reason, you should check your own spam filters as well as your [Notification Settings](https://dev.metasploit.com/redmine/my/account). If you want to follow some bug you're not already involved in, you can always tick the "Watch" star ath the top right of any issue, and you'll start getting updates every time it changes.

*TODO: Hook up Redmine updates to [Metasploit-Notifications](https://lists.sourceforge.net/lists/listinfo/metasploit-notifications) which is already watching GitHub. It'll take ten minutes.*

## Bug discussion

Some projects are persnickety about talking about bugs in the bug itself. We're not. If you have a comment or question, ask about it in the bug. We far prefer this public communication over private communication because it makes things easily searchable, captures all the information regarding an issue, and can help future bug-squashers who are searching for similar issues.

GitHub pull requests also are known to get chatty. If a bug already has a pull request associated with it, there's a very good chance there's discussion happening over there.

Finally, there are often quick conversations about current events going on on Metasploit's Freenode IRC channel, #metasploit.

Somewhat surprisingly, the [Metasploit Framework](http://mail.metasploit.com/mailman/listinfo/framework)  and the [Metasploit-Hackers](https://lists.sourceforge.net/lists/listinfo/metasploit-hackers) mailing lists don't get a lot of action in terms of issue discussion. Maybe that will change, especially if there's a move to get fascist about what kind of comments are appropriate for Redmine issues and pull requests.

## Resolving Bugs

Your bug should be considered "Resolved" once there's a fix landed in the [Metasploit-Framework master branch](https://github.com/rapid7/metasploit-framework). People who track that branch, of course, will have the fix instantly available. A few minutes after that, everyone who relies on `msfupdate` over SVN will have access to the fix. These are the bleeding-edge branches.

Once a week, usually Wednesdays, we release an update to the [Metasploit Installation](http://www.rapid7.com/downloads/metasploit.jsp). Generally speaking, Metasploit framework fixes will hit that installation on a weekly basis after appropriate QA. So, while we may refer to a bug as "resolved," it may not be available quite yet.

# EOF

That's it, for now. This document will surely change and evolve as the Metasploit community does.

***
