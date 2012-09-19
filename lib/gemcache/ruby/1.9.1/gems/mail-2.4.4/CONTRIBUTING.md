Contributing to Mail
====================

Hi there, I welcome pull requests!  Here are some thoughts on how to get your
pull request merged quickly:

1. Check the Reference RFCs, they are in the References directory, so no excuses.
2. Check for a ticket on GitHub, maybe someone else has the problem too
3. Make a fork of my GitHub repository
4. Run the specs. We only take pull requests with passing tests, and it's great
   to know that you have a clean slate: `bundle && bundle exec rake`
5. Add a spec for your change. Only refactoring and documentation changes
   require no new specs. If you are adding functionality or fixing a bug, we need
   a spec!
6. Test the spec _at_ _least_ against MRI-1.9.2 and MRI-1.8.7
7. Update the README if needed to reflect your change / addition
8. With all specs passing push your changes back to your fork
9. Send me a pull request

Note, specs that break MRI 1.8.7 will not be accepted.

At this point you're waiting on us. We like to at least comment on, if not
accept, pull requests within three business days (and, typically, one business
day). We may suggest some changes or improvements or alternatives.

Some things that will increase the chance that your pull request is accepted,
taken straight from the Ruby on Rails guide:

* Tell me you have tested it against more than one version of Ruby, RVM is great for
  this. I test against 7 rubies before I push into master.
* Use good, idiomatic, strcutred and modular code
* Include tests that fail without your code, and pass with it
* Update the documentation, the surrounding one, examples elsewhere, guides,
  whatever is affected by your contribution

Syntax:

* Two spaces, no tabs.
* No trailing whitespace. Blank lines should not have any space.
* Prefer &&/|| over and/or.
* MyClass.my_method(my_arg) not my_method( my_arg ) or my_method my_arg.
* a = b and not a=b.
* Follow the conventions you see used in the source already.

And in case we didn't emphasize it enough: we love specs!