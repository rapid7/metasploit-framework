Contributing
============
The [How to Contribute](#how-to-contribute) section of these guidelines
assume that you have at least done the following setup:
* Created a Github account.
* Set up [SSH for Github][wiki-ssh].
* Installed the [bare minimum][wiki-apt] amount of packages required by
  Metasploit.
* Set up [RVM][wiki-rvm]

If you haven't done the above then consider reading the [Metasploit
Development Environment][wiki-devenv] page, it will guide you through
the process of contributing from the beginning to submitting a pull
request.

How to Contribute
-----------------
The following is a list of the basic steps to contribute:
* Fork the ['rapid7:master'][rapid7-master] branch of the Metasploit
  Framework on Github
* Clone your fork of the Metasploit Framework: 

    `git clone https://github.com/username/metasploit-framework.git` 
* Create a branch for your contribution: 

    `git checkout -b dev_branch master` 
* Stage the changes you want to be committed: 

    `git add new_module.rb` 
* Commit with a meaningful message about your change: (Please adhere to
  [the 50/72 rule](#submitting-your-code).) 

    `git commit -m "One line commit message with meaning here."`
* Push to origin, i.e. your fork: 

    `git push origin dev_branch` 
* Go to your forked metasploit-framework repo on Github.

Once there you can find a pull request button in the top right corner,
click it, and write about how great your module is and what it does.
That's all there is to contributing to the Metasploit Framework.

What to Contribute
------------------
There are a variety of ways you could contribute to the Metasploit
Framework. If you've got something that you think would fit in go ahead
and write a module for it. If you don't know where to start you could
look at this [list of the top 50 exploits][top50] that Metasploit would
like to see contributed to the framework.

Code Style
----------

In order to maintain consistency and readability, we ask that you
adhere to the following style guidelines:

 - Hard tabs, not spaces
 - Try to keep your lines under 100 columns (assuming four-space tabs)
 - do; end instead of `{}` for a block
 - Always use `str[0,1]` instead of `str[0]`
   (This avoids a known ruby 1.8/1.9 incompatibility.)
 - Method names should always be lower_case and words separated by `_`
 - Variable names should be lower case with words separated by `_`
 - Don't depend on any external gems or libraries without talking to
   todb to resolve packaging and licensing issues 

You can use the the "./tools/msftidy.rb" script to do some rudimentary
checking for various violations.


Code No-Nos
-----------

1. Don't print to standard output. Doing so means that users of
interfaces other than msfconsole, such as msfrpc and msfgui, won't see
your output.  You can use `print_line` to accomplish the same thing as
`puts`. 

2. Don't read from standard input, doing so will make your code 
lock up the entire module when called from other interfaces. If you 
need user input, you can either register an option or expose an 
interactive session type specific

3. Don't use `sleep`. It has been known to cause issues with
multi-threaded programs on various platforms. Instead, we use
`select(nil, nil, nil, <time>)` throughout the framework. We have
found this works around the underlying issue.

4. Always use Rex sockets, not ruby sockets.  This includes
third-party libraries such as Net::Http.  There are several very good
reasons for this rule.  First, the framework doesn't get notified on
the creation of ruby sockets and won't know how to clean them up in
case your module raises an exception without cleaning up after itself.
Secondly, non-Rex sockets do not know about routes and therefore can't
be used through a meterpreter tunnel.  Lastly, regular sockets miss
out on msf's proxy and SSL features.  Msf includes many protocols
already implemented with Rex and if the protocol you need is missing,
porting another library to use them is straight-forward.  See our
Net::SSH modifications in
[lib/net/ssh/](https://github.com/rapid7/metasploit-framework/tree/master/lib/net/ssh) for an example.

5. When opening an IO stream, always force binary with "b" mode (or
using IO#binmode). This not only helps keep Windows and non-Windows
runtime environments consistent with each other, but also guarantees
that files will be treated as ASCII-8BIT instead of UTF-8.

6. Don't use String#[] for a single character.  This returns a Fixnum in
ruby 1.8 and a String in 1.9, so it's safer to use the following idiom:
	`str[idx,1]`
which always returns a String.  If you need the ASCII byte, unpack it like
so: 
	`str[idx,1].unpack("C")[0]`

7. Whenever possible, avoid using `+` or `+=` to concatenate strings.
The `<<` operator is significantly faster. The difference will become
even more apparent when doing string manipulation in a loop. The
following table approximates the underlying implementation:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ 
| Ruby       | Psuedo C                       |
|------------|--------------------------------|
|            |                                |
| a = b + c  | a = malloc(b.len+c.len+1);     |
|            | strcpy(a, b);                  |
|            | memcpy(a+b.len, c, c.len+1);   |
|            | a[b.len + c.len] = '\0';       |
| a = b      | a = b;                         |
| a << b     | a = realloc(a, a.len+c.len+1); |
|            | memcpy(a+a.len, c, c.len);     |
|            | a[a.len + c.len] = '\0';       |
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Note that the original value of 'b' is lost in the second case. Care
must be taken to duplicate strings that you do not want to modify.

8. For other Ruby 1.8.x/1.9.x compat issues, please see Sam Ruby's
excellent slide show at <http://slideshow.rubyforge.org/ruby19.html>
for an overview of common and not-so-common Ruby version related gotchas.

9. Never, ever use `$global` variables. This applies to modules, mixins,
and libraries. If you need a "global" within a specific class, you can
use `@@class_variables`, but most modules should use `@instance` variables
to store information between methods. 

10. Do not define `CONSTANTS` within individual modules. This can lead to
warning messages when the module is reloaded. Try to keep constants
inside libraries and mixins instead.


Creating New Modules
--------------------

When creating a new module, the simplest way to start is to copy
another module that uses the same protocol and modify it to your
needs.  If you're creating an exploit module, generally you'll want
to edit the `exploit()` method.  Auxiliary Scanner modules use one of
`run_host()`, `run_range()`, or `run_batch()` instead of `exploit()`.
Non-scanner aux and post modules use `run()`.

For modules, note that Author field is not automatic, and should be 
filled in in the format of `Your Name <user[at]domain.tld>` so future 
developers can contact you with any questions.

Submitting Your Code
--------------------

The process for submitting new modules via GitHub is documented here:

https://github.com/rapid7/metasploit-framework/wiki/Metasploit-Development-Environment

This describes the process of forking, editing, and generating a
pull request, and is the preferred method for bringing new modules
and framework enhancements to the attention of the core Metasploit
development team. Note that this process requires a GitHub account.

For Git commits, please adhere to 50/72 formatting: your commits should
start with a line 50 characters or less, followed by a blank line,
followed by one or more lines of explanatory text wrapped at at 72
characters Pull requests with commits not formatted this way will
be rejected without review.

`git commit` opens your editor of choice and lets you begin editing the
message. You can set your global editor by entering `git config --global
core.editor /usr/bin/vim` you can also use `:set textwidth=72` to wrap  on 72
for you in vim while writing your commit message.

Use the following resources along with the [Code Style](#code-style)
section of the contributing guidelines to ensure your code is
acceptable:

[Acceptance Guidelines][wiki-acceptance]

[Common Metasploit Module Bad Coding Practices][wiki-badcoding]

[Style Tips][wiki-styletips]

Licensing
=========
By submitting code contributions to the Metasploit Project it is
assumed that you are offering your code under the Metasploit License
or similar 3-clause BSD-compatible license.  MIT and Ruby Licenses 
are also fine.  We specifically cannot include GPL code. LGPL code
is accepted on a case by case basis for libraries only and is never 
accepted for modules.

When possible, such as aux and exploit modules, be sure to include
your license designation in the file in the appropriate place.


[rapid7-master]: https://github.com/rapid7/metasploit-framework "Metasploit Framework"
[top50]: https://dev.metasploit.com/redmine/projects/framework/wiki/Exploit_Todo#Top-50-Exploits "Top 50 Vulnerability"
[wiki-acceptance]: https://github.com/rapid7/metasploit-framework/wiki/Acceptance-Guidelines "Acceptance Guidelines"
[wiki-apt]: https://github.com/rapid7/metasploit-framework/wiki/Metasploit-Development-Environment#wiki-apt "Essentials to run Metasploit"
[wiki-badcoding]: https://github.com/rapid7/metasploit-framework/wiki/Common-Metasploit-Module-Bad-Coding-Practice "Common Metasploit Module Bad Coding Practices"
[wiki-devenv]: https://github.com/rapid7/metasploit-framework/wiki/Metasploit-Development-Environment "Metasploit Development Environment"
[wiki-rvm]: https://github.com/rapid7/metasploit-framework/wiki/Metasploit-Development-Environment#wiki-rvm "Ruby and RVM Installation"
[wiki-ssh]: https://github.com/rapid7/metasploit-framework/wiki/Metasploit-Development-Environment#wiki-ssh "SSH Configuration"
[wiki-styletips]: https://github.com/rapid7/metasploit-framework/wiki/Style-Tips "Style Tips"

