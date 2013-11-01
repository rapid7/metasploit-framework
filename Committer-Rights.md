# Metasploit Committers

The term "Metasploit Committers" describes people who have direct write access to the [Rapid7 Metasploit-Framework fork](https://github.com/rapid7/metasploit-framework). These are the people who can land changes to this main fork of the Framework. However, it is not necessary to have committer rights in order to contribute to Metasploit. Much of our code comes from non-committers.

We encourage anyone to fork the Metasploit project, make changes, fix bugs, and notify the core committers about those changes via [Pull Requests](http://github.com/rapid7/metasploit-framework/pulls). The process for getting started is most comprehensively documented in the [Metasploit Development Environment](https://github.com/rapid7/metasploit-framework/wiki/Metasploit-Development-Environment) setup guide.

Most, but not all, of the current committers are [Rapid7](http://rapid7.com) employees. We aspire to maintain a number of non-Rapid7 committers for several reasons:

1. Committers tend to contribute more material due to their enhanced status and social pressure to maintain committer rights.
2. Committers tend to feel empowered to participate in code review, help newbies, and generally be positive role models in the larger development community.
3. Committers are more likely to take up chores they might not otherwise consider -- such as writing documentation, evangelization, writing test cases, and of course, code review.
4. Outside committers can help maintain the character of the Metasploit Framework as a truly independent open source project.
5. Historically, the Metasploit Framework has enjoyed the benefits of public committers (except for most of 2012).

Ultimately, volunteerism is at the heart of the Metasploit project. The Metasploit community is built on the core belief that open contributions and open discussion of security issues has strong benefits for the Internet in general and human society as a whole. By empowering community contributors to help each other and help newcomers demonstrate security vulnerabilities and exposures, we can more effectively foster a community of excellent and ethical practitioners of information security, and incidentally drive to a higher standard of quality of the Metasploit Framework.

## What Committers Do

The primary pastime for Metasploit committers is code review. Committers tend to review pull requests that come in from other committers and from the wider Metasploit community.

Committers, despite their write access, tend to **not land their own code**. For mostly nonfunctional changes, like whitespace fixes, comment documentation, and other trivial changes, there is no need to open a pull request; such small changes happen several times a day.

For minor, major, and epic changes, committers must open pull requests just like anyone else; the reasoning for this is that at least two people should be involved in changes like this so that a) more than one person is aware of the change, and b) more than one set of eyeballs has passed over the code. This constant state of code review is crucial to the continued success of Metasploit.

Pull requests should be merged with a `git merge -S --no-ff` in order to ensure a merge commit is always generated, and your merge commit is signed with your PGP key. Clicking the green "merge" button should be avoided in order to avoid race conditions with landing code that may sneak past review, and of course, so you can sign your commits.

If a pull request is rejected, it should be absolutely clear in the pull request why it was rejected, with some effort made to point at helpful resources for next time. Most people don't often commit to open source code, so when someone does, please be respectful of their efforts.

A list of committer public keys [is here](https://github.com/rapid7/metasploit-framework/wiki/Committer-Keys).

## How to Gain Commit Rights

Commit rights are granted via a formal voting process involving all current committers, via the committers mailing list. Voting records are archived for the benefit for current and future committers.

1. Any current committer may nominate any one person as a potential committer by writing to the mailing list. The nominator generally should not inform the nominee that she has been nominated until after a successful vote in the nominee's favor. The nominator must provide a justification for committer rights, and include the nominee's e-mail address.
2. Any current committer may veto the nominee for any (or no) reason.
3. The chief architect of Metasploit Framework [HD Moore](https://github.com/hmoore-r7), the engineering manager [Tod Beardsley](https://github.com/todb-r7), and the senior engineer [James "Egypt" Lee](https://github.com/jlee-r7), must all affirm the nominee within a week on the mailing list with a yes vote -- otherwise, the nomination suffers a pocket veto.
4. The engineering manager will inform the nominee of his new commit rights and responsibilities, add the new committer to the appropriate ACL groups and mailing lists, and inform the mailing list of the successful completion of these tasks.

Committers introduced in this way will have commit rights to the following repositories:

 * https://github.com/rapid7/metasploit-framework
 * https://github.com/rapid7/meterpreter
 * https://github.com/rapid7/metasploit-javapayload

## How to Lose Commit Rights

Committer rights are not granted strictly on the basis of proven code quality; committer rights are a statement of trust by the existing body of committers, so there are highly subjective criteria in play as well. Elements like an agreeable personality, the ability to remain calm in the face of trolling, the avoidance of criminal proceedings, and other aspects of a committer's life all play a part in the initial granting of commit access.

The one exception is simple inactivity and a lack of commits. Inactivity for six months will engender an e-mail from the engineering manager reminding the committer of her rights and the risk exposure of having rights but not using them. No response to this e-mail will lead to the loss of the rights, since the committer is clearly not reachable and may or may not have been compromised.

Otherwise, breaches of trust in terms of malicious or malformed code, or the demonstration of poor judgement that would reflect poorly on the Metasploit project will lead to a discussion on the committer mailing list, and which is likely result in the removal of committer rights.

## Useful Links for Committers

  * Check out the Apache Software Foundation's [Guide for Committers](https://www.apache.org/dev/committers). It's illuminating.
  * [Producing Open Source Software](http://www.producingoss.com/gl/) by Ken Fogel is a must-read.
  * Zach Holman's [Open Source Misfeasance](https://speakerdeck.com/holman/open-source-misfeasance) slides -- the video is gone!
  * [How to Survive Poisonous People](https://www.youtube.com/watch?v=Q52kFL8zVoM) by Ben Collins-Sussman and Brian Fitzpatrick
  * [The Netiquette RFC](http://www.faqs.org/rfcs/rfc1855.html) is about how to be polite.