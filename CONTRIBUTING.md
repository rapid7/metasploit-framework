# Contributing to Metasploit

The following is a list of rules for contributing to Metasploit.

If you cannot follow these rules, your pull request or bug report **will** be closed (*Road House* style).

First of all, read the [wiki](https://github.com/rapid7/metasploit-framework/wiki). You don't have to read all of it, but you should read the parts that are relevant to you.

If you don't know where to start, you should read the [development environment setup guide](https://github.com/rapid7/metasploit-framework/wiki/Setting-Up-a-Metasploit-Development-Environment).

## Code Contributions

* **Do** follow the [Ruby style guide](https://github.com/bbatsov/ruby-style-guide)
* **Do** follow the [HACKING](HACKING) guide

### Pull Requests

* **Do** include [console output](https://help.github.com/articles/github-flavored-markdown#fenced-code-blocks) - example runs are useful
* **Do** include [verification steps](https://help.github.com/articles/writing-on-github#task-lists) - this greatly helps with testing
* **Do not** leave your pull request description blank
* **Do not** abandon your pull request - being responsive helps us land your code faster

#### New Modules

* **Do** run `tools/msftidy.rb` against your module and fix any errors or warnings that come up
* **Do** use the [API](https://dev.metasploit.com/documents/api/) - don't reinvent the wheel (you can improve it, though)
* **Do not** include more than one module per pull request

#### Library Code

* **Do** write [RSpec](http://rspec.info/) tests - even the smallest change in library land can thoroughly screw things up
* **Do** follow [Better Specs](http://betterspecs.org/) - it's like the style guide for specs
* **Do** write [YARD](http://yardoc.org/) documentation - this makes it easier for people to use your code

#### Bug Fixes

* **Do** include reproduction steps in the form of verification steps
* **Do** include a link to the corresponding [Redmine](https://dev.metasploit.com/redmine/projects/framework) issue, if any

## Bug Reports

* **Do** create a Redmine account and report your bug there
* **Do** write a detailed description of your bug
* **Do** include reproduction steps, stack traces, and anything else that might help us verify and fix your bug
* **Do not** file duplicate reports - search for your bug before filing a new report
* **Do not** report a bug on GitHub - we don't track bugs on GitHub

If you need help, talk to us on IRC at **#metasploit on freenode** or e-mail us at msvdev@metasploit.com.
