# Metasploit Bug Reporting

Metasploit gets hundreds of issue reports every year on our [issue tracker](https://github.com/rapid7/metasploit-framework/issues). Some issues aren't bug reports at all, but instead requests for new features or questions about Metasploit usage. We appreciate feature or enhancement requests, and you should feel free to keep submitting those to our issue tracker. Some questions, such as whether an odd error or behavior is intended, are okay to submit to the issue tracker as well. Other questions, such as basic support requests or questions on beginning Framework usage, are better to ask the community on [Slack](https://metasploit.com/slack). If you believe you have discovered a legitimate bug in Metasploit Framework, you should open a bug report on our [issue tracker](https://github.com/rapid7/metasploit-framework/issues). The rest of this page will discuss how to submit detailed, useful bug reports so we can understand and triage your issue as quickly as possible.

But first...two important exceptions to bug/issue reports.

## When NOT to use Metasploit's issue tracker
**NOTE:** There are two situations where, even if you have found what you know is a bug, you should not open a bug report on our public issue tracker.
1. You should not open a bug report on Metasploit Framework's issue tracker if you are a Metasploit Pro customer.
2. You should not open a bug report when you have found a security issue with Metasploit itself.

### Metasploit Pro Customers
If you are a Metasploit Pro customer, you can log in to Rapid7's customer support portal [here](https://www.rapid7.com/for-customers/). You are also able to reach out to your CSM or support representative if you prefer. To provide a consistent customer experience, Metasploit Framework community members, committers, and open-source developers do not offer support for commercial Rapid7 products. Rapid7's support resources and team members are well-equipped to handle your Metasploit Pro support needs!

### Security Issues
If you have a security issue with Metasploit itself, you should email security@rapid7.com or let us know [here](https://www.rapid7.com/security/). Rapid7's disclosure policy is [here](https://www.rapid7.com/security/disclosure/). In general, our security teams are happy to give you credit, inform you about progress, and explore related issues with you if you'd like. They're also happy to keep you anonymous if that's what you prefer. All of this is significantly easier if you report security issues in a manner that lets our teams quickly work with you to understand the problem! Clear communication and coordinated disclosure give us the best chance of fixing any security issues quickly and protecting users.

Now on to the good stuff! The Metasploit development community has read thousands of bug reports over the past 15 years, and a well-written bug report makes fixing bugs much faster and easier. In fact, in our experience, how quickly we can understand and fix an issue has more to do with bug report quality than the complexity of the bug itself.

## General Rules
* Ensure the platform you're reporting the issue for is supported. We do not, for instance, support Termux currently. If your platform is not officially supported, the community may still have resources to help, but you should search for and ask about those outside Metasploit's issue tracker.
* When possible, it helps if you are running the latest stable version of Metasploit Framework, or the latest release of Kali, BlackArch Linux, or your other favorite security distribution that ships with Metasploit. Metasploit's [[nightly installers are here|./Nightly-Installers.md]] and typically offer the latest Framework release.
* Review our [[code of conduct|./Code-Of-Conduct.md]] before submitting issues.
* Use a specific title so we can understand immediately which part of Metasploit is causing the unexpected behavior. "NoMethodError raised on smb_login module" is a great title. "Problem with Metasploit target" is not.
* Redact any private or sensitive data, such as target IPs or URLs, passwords, or personally identifying information.
* Please don't comment on closed issues; instead, open a new issue and link to any previous relevant issues.

## Information to Include
We ask for several different pieces of information when users report issues in Metasploit. As of June 2020, our core engineering team in Belfast is developing a `debug` command that will automatically give you all the information we require when you encounter an issue and then run the command in msfconsole. For now, the following information ensures that we can more effectively triage and address bugs. **If you do not provide this information, it is likely that response time will be significantly longer!**

### Steps to reproduce
What did you do to get the results you got? Can you give us step-by-step instructions to get the same results you got? Are you able to consistently reproduce the issue in your own environment?

### Which OS are you using? What do we need to know about your environment and/or target?
Tell us which operating system you're using and any relevant information about your setup. If the module or feature you're having trouble with requires any external dependencies, check whether they are installed, and (if not) whether installing them could solve your problem.

If you're having problems with a target (victim), tell us the target operating system and service versions.(Please ensure you've redacted any private or sensitive data!) If the module or feature you're having trouble with requires any external dependencies, check whether that could solve your problem.

If you're testing a module in a lab or virtual environment, we would appreciate as much data about the target as you can provide. This means exact versions of the target including patch levels, pcaps if you can capture them, and any kind of logging inside or outside of Framework. We will often ask for the `framework.log`.

### Expected behavior
What should happen? If what you're trying to do used to work but no longer does, what was the behavior you encountered _before_ you ran into a problem?

### Current behavior
What happens now? Please give us as many technical details as possible. Once again, we also strongly recommend that you send us any relevant logs and/or stack traces. In case you haven't noticed by now, we absolutely love logs and screen captures, and your including them will make us happy.

### Metasploit version
Get this with the `version` command in msfconsole (or `git log -1 --pretty=oneline` for a source install).
Did you install Metasploit with...
- [ ] Kali package via apt
- [ ] Omnibus installer (nightly)
- [ ] Commercial installer (from <https://www.rapid7.com/products/metasploit/download/>)
- [ ] Source install (please specify Ruby version)

This list isn't intended to be exhaustive - it's simply the bare minimum set of details we need to reproduce and diagnose your bug. You should feel free to include as much detailed information as you need to help us understand how you got the results you did.

## Avoid Duplicates
You may not be the first person to notice the problem you're seeing as a Framework user, and the more bug reports we get, the more difficult it is to sort through them all for easy fixes or high-priority issues. Here are some ways to help a previously-reported bug get noticed more quickly and prioritized (if necessary).

* Having a problem with a module? Try [searching that module's name](https://github.com/rapid7/metasploit-framework/issues?q=is%3Aissue+is%3Aopen+psexec) to see if anyone else has reported (or fixed!) your problem recently.
* Getting a strange error and not sure what it means? [Search for the error](https://github.com/rapid7/metasploit-framework/issues?q=is%3Aissue+URI.unescape) to see if others have had or addressed the same problem you are facing.
* Pro tip: Search both [open and closed issues](https://github.com/rapid7/metasploit-framework/issues?q=is%3Aissue) to see if what you're reporting was resolved (in which case you might simply need to update to a later version of Metasploit) or if there's a workaround someone else has discovered that might help you while we get to your issue.
* If you DO discover that someone else has already reported the issue you're experiencing, please do update that issue with any new information - for instance, that you're experiencing the issue on a different OS or in a different version of Metasploit than what the original issue reports described.
* If you find closed issues or resolved bugs that describe a problem you're having on a later version of Metasploit, that could indicate a regression (old bugs that have been reintroduced). It helps us if you note this in your issue report. Fixes for regressions can be fast, so making note of possible regressions is useful.
* Finally, you might find a bug that's been rejected or closed without resolution. In many of these cases, the problem is something external to Metasploit: user error, configuration issues, known incompatibilities, etc. If you think that the original resolution was in error or incomplete, open a **new** issue report and refer to any related issue reports.

## Other Notes
* Networking is hard, as we've often said even among ourselves! You might want to see if your network configuration is unusual in any way, or do a regular old internet search to check whether your config might be the problem.
* Antivirus frequently causes strange behavior. Ensure antivirus is disabled on your system or in any VMs where you're using Metasploit.
* GitHub pull requests frequently contain a LOT of conversation and context. If a bug already has a pull request associated with it, check the pull request conversation for other information that might be useful to you.

## PRs Accepted!

If you're a superhero and you figured out the root cause of a bug AND found a way to fix it, you can send your Metasploit fixes and improvements our way! The best way to get your fix into Metasploit quickly is to patch your own fork and submit a pull request to Metasploit. You get extra gratitude from all of us when you do this, and you'll also get a shout-out in the [weekly Metasploit wrap-up](https://blog.rapid7.com/tag/metasploit-weekly-wrapup/).

You can find a guide on setting up your own [[Metasploit Development Environment here|./dev/Setting-Up-a-Metasploit-Development-Environment.md]].

## Public Discussion
Some projects and companies don't like discussing bugs in the bug report itself. Some even have policies of not doing this. Metasploit is not one of those projects. We greatly prefer public communication over private communication because it makes community knowledge accessible and searchable to everyone. That said, if you have specific privacy or security concerns, we're always happy to speak privately. You can get in touch with us at msfdev@metasploit.com.

## Resolved Bugs
Your bug should be considered "Resolved" once there's a fix landed in the [Metasploit-Framework master branch](https://github.com/rapid7/metasploit-framework). People who track that branch will have the fix available quickly. It may take other distributions that include Metasploit (e.g., Kali) a few days to pull in fixes, depending on their individual release cadences.

Thanks for helping us get to diagnoses and resolutions quickly and efficiently for all Framework users!
