# Like hacking things? Start here.

Every so often, we'll get a request along the lines of, "Hey, I'm new to Metasploit, and I want to help!" The usual answer is something like, "Great! Here's our [framework bug tracker](https://github.com/rapid7/metasploit-framework/issues), get crackin!"

However, tackling core Metasploit Framework bugs or particularly squirrelly exploits probably isn't the right place for the new contributor. Believe me, everyone was a newbie once, there's no shame in that. Those bugs and vulns are usually complicated, and there are so many to choose from that it's hard to get started. Here are some ideas to get you started.

Metasploit is a tool by and for hackers, but the hackers that maintain it also happen to be software engineers. So, we have some hopefully easy-to-remember Do's and Don'ts in [CONTRIBUTING.md](https://github.com/rapid7/metasploit-framework/blob/master/CONTRIBUTING.md). Read up on those.

# Server exploits

Server exploits are always in demand; why bother with complicated social engineering campaigns when you can go straight to the pain point of a vulnerable network. Here are some search queries to get you started:

 * [Remote exploits](https://www.exploit-db.com/?type=remote) from Exploit-DB

# Client Exploits

Client exploits generally run as an "evil service" that a remote client will connect to. They nearly always require some kind of user interaction to trigger, such a viewing a web page, downloading a file, or otherwise connecting to the service controlled by the attacker.

 * [Browser Vulns](https://www.google.com/#bav=on.2,or.r_cp.r_qf.&q=site:securityfocus.com+%22Firefox%22+OR+%22Internet+Explorer%22+OR+%22Chrome%22+OR+%22Safari%22+OR+%22Opera%22+-%22Retired%22&safe=off) from SecurityFocus via Google search terms

# Local and Privilege Escalation Exploits

Privilege escalation exploits tend to require the attacker already have an account on a target computer. They are nearly always going to be implemented as Metasploit exploit modules under one of the [local](https://github.com/rapid7/metasploit-framework/tree/master/modules/exploits/windows/local) trees (platform dependent), but sometimes they're better off as [post modules](https://github.com/rapid7/metasploit-framework/tree/master/modules/post). This is especially true for privilege escalation bugs.

 * [Local Vulns](https://www.exploit-db.com/?type=local) from Exploit-DB

# Unstable modules

Want to pick up where someone else left off? Super! Just check the guide on rescuing [[Unstable Modules]] and push these poor, unloved modules over the finish line with decent testing and code cleanup.

# Framework bugs and features

If exploit dev isn't your thing, but more straightforward Ruby development is, then here are some good places to get started:

 * [Recent Bugs](https://github.com/rapid7/metasploit-framework/issues?q=is%3Aissue+is%3Aopen+label%3Abug), which tend to be either very easy or very hard to fix (not a lot of middle ground).
 * [Feature requests](https://github.com/rapid7/metasploit-framework/issues?q=is%3Aissue+is%3Aopen+label%3Afeature), which is often in the same boat.

Along these same lines is a perennial need for better automated testing, down in the [spec directory](https://github.com/rapid7/metasploit-framework/tree/master/spec). If you have a talent for exploring strange and wonderful code bases, pick out a chunk of the Metasploit core code and define out what you expect for working behavior.

# Non-code

We can always use better documentation. Those guys over at Offensive Security do a great job with [Metasploit Unleashed](http://www.offensive-security.com/metasploit-unleashed/Main_Page), but as with all complex bodies of work, there are surely bugs to be found. If you have ideas on how to make the documentation on Metasploit clear and more accessible to more people, go nuts. 

Write wiki articles in your fork (hint, [Gollum](https://github.com/gollum/gollum) is excellent for this) and let someone know about them, we'll be happy to reflect them here and maintain your credit. If you're interested in working with us on documentation long-term, that's even better; reach out on [Slack](https://metasploit.com/slack) for info on how best to make changes.

Ditto with YouTube screencasts of particular common tasks. Narration while you do it is great. People seem to love YouTube videos of this stuff -- there are over [40,000](http://www.youtube.com/results?search_query=metasploit&oq=metasploit) of the things out there, and we'd love for someone to step up and curate a top 10 or top 100 of those that we can promote here for new and experienced users.

For developer types: we are slowly but surely converting all of Metasploit to use standardized commenting using [YARD](yardoc.org), so we could always use more accurate and more comprehensive YARD documentation for pretty much anything found in `lib`. We will happily take pull requests that contain nothing but comment docs!

Again, there's always room on #metasploit on Freenode. Be helpful with the questions there, and people are more likely to help you in the future. Same goes for the [Metasploit Slack team](https://metasploit.com/slack), where all sorts of new and proficient users and devs are looking for help and camaraderie. 

# The Usual Warnings

You probably shouldn't run proof of concept exploit code you find on the Internet on a machine you care about in a network you care about. That is generally considered a Bad Idea. You also probably shouldn't use your usual computer as a target for exploit development, since you are intentionally inducing unstable behavior.

Our preferred method of module submission is via a git pull request from a feature branch on your own fork of Metasploit.  You can learn how to create one here:
https://github.com/rapid7/metasploit-framework/wiki/Landing-Pull-Requests

Also, please take a peek at our guides on using git and our acceptance guidelines for new modules in case you're not familiar with them:
https://github.com/rapid7/metasploit-framework/wiki

If you get stuck, try to explain your specific problem as best you can on our [Freenode IRC](https://freenode.net/) channel, #metasploit (joining requires a [registered nick](https://freenode.net/kb/answer/registration)). Someone should be able to lend a hand. Apparently, some of those people never sleep.

# Thank you

In case nobody's said it yet: Thanks for your interest and support! Exploit developers from the open source community are the soul of Metasploit, and by contributing your time and talent, you are helping advance the state of the art for intelligent IT defense. We simply couldn't do all of this without you.