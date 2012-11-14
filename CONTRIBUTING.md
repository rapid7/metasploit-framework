# Contributing to Metasploit

## Reporting Bugs

If you would like to report a bug, please take a look at [our Redmine
issue
tracker](https://dev.metasploit.com/redmine/projects/framework/issues?query_id=420)
-- your bug may already have been reported there! Simply [searching](https://dev.metasploit.com/redmine/projects/framework/search) for some appropriate keywords may save everyone a lot of hassle.

If your bug is new and you'd like to report it you will need to
[register
first](https://dev.metasploit.com/redmine/account/register). Don't
worry, it's easy and fun and takes about 30 seconds.

## Contributing Metasploit Modules

If you have an exploit that you'd like to contribute to the Metasploit
Framework, please familiarize yourself with the
[HACKING](https://github.com/rapid7/metasploit-framework/blob/master/HACKING)
document in the
Metasploit-Framework repository. There are many mysteries revealed in
HACKING concerning code style and content.

[Pull requests](https://github.com/rapid7/metasploit-framework/pulls)
should corellate with modules at a 1:1 ratio
-- there is rarely a good reason to have two, three, or ten modules on
one pull request, as this dramatically increases the review time
required to land (commit) any of those modules.

Pull requests tend to be very collaborative for Metasploit -- do not be
surprised if your pull request to rapid7/metasploit-framework triggers a
pull request back to your own fork. In this way, we can isolate working
changes before landing your PR to the Metasploit master branch.
