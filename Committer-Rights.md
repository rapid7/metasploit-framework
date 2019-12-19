# Metasploit Committers

The term "Metasploit Committers" describes people who have direct write access to the [Rapid7 Metasploit-Framework fork](https://github.com/rapid7/metasploit-framework). These are the people who can land changes to this main fork of the Framework. However, it is not necessary to have committer rights in order to contribute to Metasploit. Much of our code comes from non-committers.

We encourage anyone to fork the Metasploit project, make changes, fix bugs, and notify the core committers about those changes via [Pull Requests](http://github.com/rapid7/metasploit-framework/pulls). The process for getting started is most comprehensively documented in the [Metasploit Development Environment](https://github.com/rapid7/metasploit-framework/wiki/Metasploit-Development-Environment) setup guide.

Metasploit committers are a mix of [Rapid7](http://rapid7.com) employees and outside contributors. Anyone can become a contributor, with the following expectations:

1. Committers are empowered to participate in code review, help newbies, and be positive role models in the larger development community.
2. Committers are likely to take up chores such as writing documentation, evangelization, writing test cases, and code review.
3. Committers help maintain the character of the Metasploit Framework as a truly independent open source project.

The Metasploit community is built on the core belief that open contributions and open discussion of security issues has strong benefits for the Internet in general and human society as a whole. By helping each other demonstrate security vulnerabilities and exposures, we foster a community of excellent, ethical practitioners of information security.

# How to be a Committer

Committers tend to review pull requests that come in from other committers and from the wider Metasploit community. Committers generally should not land their own code without some sort of review from another contributor or committer.

For most changes, please open a pull request. In addition, always ask for someone to review your work. Even simple fixes might be better done otherwise. If you get no feedback on your pull requests, ask again. Be annoying if necessary! Don't submit a pull request or make a comment and let it rot because nobody responds.

Pull requests should be merged with a `git merge -S --no-ff` in order to ensure a merge commit is always generated, and your merge commit is signed with your PGP key. Avoid clicking the green "merge" button in Github in order to avoid race conditions with landing code that may sneak past review, and of course, so you can sign your commits.

If you reject a pull request, be clear in the pull request why it was rejected, with some effort made to point at helpful resources for next time. Most people don't often commit to open source code, so when someone does, please be respectful of their efforts.

Even if someone else approves of a pull request, and it is shown to be broken later, then it is still your responsibility to correct it. Make every effort to get a fix or revert in as soon as possible, whether you wrote the code, landed it, or approved it. Blame is shared equally.

A list of committer public keys [is here](https://github.com/rapid7/metasploit-framework/wiki/Committer-Keys).

# How to Gain Commit Rights

Commit rights are granted via votes on the committers mailing list. Voting records are archived for the benefit for current and future committers.

1. Any current committer may nominate any one person as a potential committer by writing to the committers mailing list.
2. The nominator must provide a justification for committer rights, and include the nominee's e-mail address.
2. After some discussion on the mailing list, there will be a group vote on the nominee.
2. The Metasploit manager (@busterb) will inform the new committer of their new commit rights and responsibilities, add the new committer to the appropriate ACL groups and mailing lists, and inform the mailing list of the successful completion of these tasks.

Committers introduced in this way will have commit rights to the [public framework repositories](https://github.com/orgs/rapid7/teams/framework-public-committers/repositories).

# How to Lose Commit Rights

Committer rights are not granted strictly on the basis of proven code quality; committer rights are a statement of trust by the existing body of committers, so there are highly subjective criteria in play as well. Elements like an agreeable personality, the ability to remain calm in the face of trolling, the avoidance of criminal proceedings, and other aspects of a committer's life all play a part in the initial granting of commit access.

Breaches of trust in terms of malicious or malformed code, or the demonstration of poor judgement that would reflect poorly on the Metasploit project will lead to a discussion on the committer mailing list, and which is likely result in the removal of committer rights.

# Useful Links for Committers

  * [http://r-7.co/MSF-DEV](https://github.com/rapid7/metasploit-framework/wiki/Setting-Up-a-Metasploit-Development-Environment) is pretty much required reading.
  * So is [CONTRIBUTING.md](https://github.com/rapid7/metasploit-framework/blob/master/CONTRIBUTING.md)
  * Check out the Apache Software Foundation's [Guide for Committers](https://www.apache.org/dev/committers). It's illuminating.
  * [Producing Open Source Software](http://www.producingoss.com/gl/) by Ken Fogel is a must-read.
  * Zach Holman's [Open Source Misfeasance](https://speakerdeck.com/holman/open-source-misfeasance) slides -- the video is gone!
  * [How to Survive Poisonous People](https://www.youtube.com/watch?v=Q52kFL8zVoM) by Ben Collins-Sussman and Brian Fitzpatrick
  * [The Netiquette RFC](http://www.faqs.org/rfcs/rfc1855.html) is about how to be polite.
