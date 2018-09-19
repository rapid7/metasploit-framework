# Hello, World!

Thanks for your interest in making Metasploit -- and therefore, the
world -- a better place!

Are you about to report a bug? Sorry to hear it. Here's our [Issue tracker].
Please try to be as specific as you can about your problem; include steps
to reproduce (cut and paste from your console output if it's helpful) and
what you were expecting to happen.

Are you about to report a security vulnerability in Metasploit itself?
How ironic! Please take a look at Rapid7's [Vulnerability
Disclosure Policy](https://www.rapid7.com/disclosure.jsp), and send
your report to security@rapid7.com using our [PGP key].

Are you about to contribute some new functionality, a bug fix, or a new
Metasploit module? If so, read on...

# Contributing to Metasploit

What you see here in CONTRIBUTING.md is a bullet point list of the do's
and don'ts of how to make sure *your* valuable contributions actually
make it into Metasploit's master branch.

If you care not to follow these rules, your contribution **will** be
closed. Sorry!

This is intended to be a **short** list. The [wiki] is much more
exhaustive and reveals many mysteries. If you read nothing else, take a
look at the standard [development environment setup] guide
and Metasploit's [Common Coding Mistakes].

## Code Contributions

* **Do** stick to the [Ruby style guide].
* **Do** get [Rubocop] relatively quiet against the code you are adding or modifying.
* **Do** follow the [50/72 rule] for Git commit messages.
* **Don't** use the default merge messages when merging from other branches.
* **Do** license your code as BSD 3-clause, BSD 2-clause, or MIT.
* **Do** create a [topic branch] to work on instead of working directly on `master`.
 If you do not send a PR from a topic branch, the history of your PR will be
 lost as soon as you update your own master branch. See
 https://github.com/rapid7/metasploit-framework/pull/8000 for an example of
 this in action.


### Pull Requests

* **Do** target your pull request to the **master branch**. Not staging, not develop, not release.
* **Do** specify a descriptive title to make searching for your pull request easier.
* **Do** include [console output], especially for witnessable effects in `msfconsole`.
* **Do** list [verification steps] so your code is testable.
* **Do** [reference associated issues] in your pull request description.
* **Do** write [release notes] once a pull request is landed.
* **Don't** leave your pull request description blank.
* **Don't** abandon your pull request. Being responsive helps us land your code faster.

Pull requests [PR#2940] and [PR#3043] are a couple good examples to follow.

#### New Modules

* **Do** run `tools/dev/msftidy.rb` against your module and fix any errors or warnings that come up.
  - It would be even better to set up `msftidy.rb` as a [pre-commit hook].
* **Do** use the many module mixin [API]s. Wheel improvements are welcome; wheel reinventions, not so much.
* **Don't** include more than one module per pull request.
* **Do** include instructions on how to setup the vulnerable environment or software.
* **Do** include [Module Documentation](https://github.com/rapid7/metasploit-framework/wiki/Generating-Module-Documentation) showing sample run-throughs.



#### Scripts

* **Don't** submit new [scripts].  Scripts are shipped as examples for
  automating local tasks, and anything "serious" can be done with post
  modules and local exploits.

#### Library Code

* **Do** write [RSpec] tests - even the smallest change in library land can thoroughly screw things up.
* **Do** follow [Better Specs] - it's like the style guide for specs.
* **Do** write [YARD] documentation - this makes it easier for people to use your code.
* **Don't** fix a lot of things in one pull request. Small fixes are easier to validate.

#### Bug Fixes

* **Do** include reproduction steps in the form of verification steps.
* **Do** include a link to any corresponding [Issues] in the format of
  `See #1234` in your commit description.

## Bug Reports

* **Do** report vulnerabilities in Rapid7 software directly to security@rapid7.com.
* **Do** write a detailed description of your bug and use a descriptive title.
* **Do** include reproduction steps, stack traces, and anything else that might help us verify and fix your bug.
* **Don't** file duplicate reports; search for your bug before filing a new report.

If you need some more guidance, talk to the main body of open
source contributors over on the [Freenode IRC channel],
or e-mail us at the [metasploit-hackers] mailing list.

Also, **thank you** for taking the few moments to read this far! You're
already way ahead of the curve, so keep it up!

[Issue Tracker]:http://r-7.co/MSF-BUGv1
[PGP key]:http://pgp.mit.edu:11371/pks/lookup?op=vindex&search=0x2380F85B8AD4DB8D
[wiki]:https://github.com/rapid7/metasploit-framework/wiki
[scripts]:https://github.com/rapid7/metasploit-framework/tree/master/scripts
[development environment setup]:http://r-7.co/MSF-DEV
[Common Coding Mistakes]:https://github.com/rapid7/metasploit-framework/wiki/Common-Metasploit-Module-Coding-Mistakes
[Ruby style guide]:https://github.com/bbatsov/ruby-style-guide
[Rubocop]:https://rubygems.org/search?query=rubocop
[50/72 rule]:http://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html
[topic branch]:http://git-scm.com/book/en/Git-Branching-Branching-Workflows#Topic-Branches
[console output]:https://help.github.com/articles/github-flavored-markdown#fenced-code-blocks
[verification steps]:https://help.github.com/articles/writing-on-github#task-lists
[reference associated issues]:https://github.com/blog/1506-closing-issues-via-pull-requests
[release notes]:https://github.com/rapid7/metasploit-framework/wiki/Adding-Release-Notes-to-PRs
[PR#2940]:https://github.com/rapid7/metasploit-framework/pull/2940
[PR#3043]:https://github.com/rapid7/metasploit-framework/pull/3043
[pre-commit hook]:https://github.com/rapid7/metasploit-framework/blob/master/tools/dev/pre-commit-hook.rb
[API]:https://rapid7.github.io/metasploit-framework/api
[RSpec]:http://rspec.info
[Better Specs]:http://betterspecs.org
[YARD]:http://yardoc.org
[Issues]:https://github.com/rapid7/metasploit-framework/issues
[Freenode IRC channel]:http://webchat.freenode.net/?channels=%23metasploit&uio=d4
[metasploit-hackers]:https://groups.google.com/forum/#!forum/metasploit-hackers
