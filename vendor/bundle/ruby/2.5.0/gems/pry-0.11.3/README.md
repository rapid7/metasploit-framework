[![Build Status](https://img.shields.io/travis/pry/pry.svg)](https://travis-ci.org/pry/pry)
[![Code Climate](https://img.shields.io/codeclimate/github/pry/pry.svg)](https://codeclimate.com/github/pry/pry)
[![Inline docs](http://inch-ci.org/github/pry/pry.svg?style=shields)](http://inch-ci.org/github/pry/pry)
<br><br>
![logo for Pry](https://dl.dropbox.com/u/26521875/pry%20stuff/logo/pry_logo_350.png)

© John Mair ([banisterfiend](https://twitter.com/banisterfiend)) 2016<br>

**Please** [DONATE](http://pledgie.com/campaigns/15899) to the Pry project - Pry was a **huge** amount of work and every donation received is encouraging and supports Pry's continued development!

**Sponsors**

[Launch School](https://launchschool.com)<br/>
[Atomic Object](https://atomicobject.com/)<br/>
[Hashrocket](https://hashrocket.com/)<br/>
[Intridea](http://www.intridea.com)<br/>
[Gaslight](https://teamgaslight.com)<br/>

**Other Resources**

[Skip to the website (recommended)](http://pryrepl.org/) <br />
[Skip to the wiki](https://github.com/pry/pry/wiki)


Pry is a powerful alternative to the standard IRB shell for Ruby. It is
written from scratch to provide a number of advanced features,
including:

* Source code browsing (including core C source with the pry-doc gem)
* Documentation browsing
* Live help system
* Open methods in editors (`edit Class#method`)
* Syntax highlighting
* Command shell integration (start editors, run git, and rake from within Pry)
* Gist integration
* Navigation around state (`cd`, `ls` and friends)
* Runtime invocation (use Pry as a developer console or debugger)
* Exotic object support (BasicObject instances, IClasses, ...)
* A Powerful and flexible command system
* Ability to view and replay history
* Many convenience commands inspired by IPython, Smalltalk and other advanced REPLs
* A wide-range number of [plugins](https://github.com/pry/pry/wiki/Available-plugins) that provide remote sessions, full debugging functionality, and more.

Pry also aims to be more than an IRB replacement; it is an
attempt to bring REPL driven programming to the Ruby language. It is
currently not as powerful as tools like [SLIME](https://en.wikipedia.org/wiki/SLIME) for lisp, but that is the
general direction Pry is heading.

Pry is also fairly flexible and allows significant user
[customization](https://github.com/pry/pry/wiki/Customization-and-configuration)
is trivial to set it to read from any object that has a `readline` method and write to any object that has a
`puts` method - many other aspects of Pry are also configurable making
it a good choice for implementing custom shells.

Pry comes with an executable so it can be invoked at the command line.
Just enter `pry` to start. A `.pryrc` file in the user's home directory will
be loaded if it exists. Type `pry --help` at the command line for more
information.

Try `gem install pry-doc` for additional documentation on Ruby Core
methods. The additional docs are accessed through the `show-doc` and
`show-method` commands.

* Install the [gem](https://rubygems.org/gems/pry): `gem install pry`
* Browse the comprehensive [documentation at the official Pry wiki](https://github.com/pry/pry/wiki)
* Read the [YARD API documentation](http://www.rubydoc.info/github/pry/pry/)
* See the [source code](https://github.com/pry/pry)

### Commands

Nearly every piece of functionality in a Pry session is implemented as
a command. Commands are not methods and must start at the beginning of a line, with no
whitespace in between. Commands support a flexible syntax and allow
'options' in the same way as shell commands, for example the following
Pry command will show a list of all private instance methods (in
scope) that begin with 'pa'

    pry(YARD::Parser::SourceParser):5> ls -Mp --grep ^pa
    YARD::Parser::SourceParser#methods: parse  parser_class  parser_type  parser_type=  parser_type_for_filename

### Navigating around state

Pry allows us to pop in and out of different scopes (objects) using
the `cd` command. This enables us to explore the run-time view of a
program or library. To view which variables and methods are available
within a particular scope we use the versatile [ls command.](https://gist.github.com/c0fc686ef923c8b87715)

Here we will begin Pry at top-level, then Pry on a class and then on
an instance variable inside that class:

    pry(main)> class Hello
    pry(main)*   @x = 20
    pry(main)* end
    => 20
    pry(main)> cd Hello
    pry(Hello):1> ls -i
    instance variables: @x
    pry(Hello):1> cd @x
    pry(20):2> self + 10
    => 30
    pry(20):2> cd ..
    pry(Hello):1> cd ..
    pry(main)> cd ..

The number after the `:` in the pry prompt indicates the nesting
level. To display more information about nesting, use the `nesting`
command. E.g

    pry("friend"):3> nesting
    Nesting status:
    0. main (Pry top level)
    1. Hello
    2. 100
    3. "friend"
    => nil

We can then jump back to any of the previous nesting levels by using
the `jump-to` command:

    pry("friend"):3> jump-to 1
    => 100
    pry(Hello):1>

### Runtime invocation

Pry can be invoked in the middle of a running program. It opens a Pry
session at the point it's called and makes all program state at that
point available. It can be invoked on any object using the
`my_object.pry` syntax or on the current binding (or any binding)
using `binding.pry`. The Pry session will then begin within the scope
of the object (or binding). When the session ends the program continues with any
modifications you made to it.

This functionality can be used for such things as: debugging,
implementing developer consoles and applying hot patches.

code:

```ruby
# test.rb
require 'pry'

class A
  def hello() puts "hello world!" end
end

a = A.new

# start a REPL session
binding.pry

# program resumes here (after pry session)
puts "program resumes here."
```

Pry session:

    pry(main)> a.hello
    hello world!
    => nil
    pry(main)> def a.goodbye
    pry(main)*   puts "goodbye cruel world!"
    pry(main)* end
    => nil
    pry(main)> a.goodbye
    goodbye cruel world!
    => nil
    pry(main)> exit

    program resumes here.

### Command Shell Integration

A line of input that begins with a '.' will be forwarded to the
command shell. This enables us to navigate the file system, spawn
editors, and run git and rake directly from within Pry.

Further, we can use the `shell-mode` command to incorporate the
present working directory into the Pry prompt and bring in (limited at this stage, sorry) file name completion.
We can also interpolate Ruby code directly into the shell by
using the normal `#{}` string interpolation syntax.

In the code below we're going to switch to `shell-mode` and edit the
`.pryrc` file in the home directory. We'll then cat its contents and
reload the file.

    pry(main)> shell-mode
    pry main:/home/john/ruby/projects/pry $ .cd ~
    pry main:/home/john $ .emacsclient .pryrc
    pry main:/home/john $ .cat .pryrc
    def hello_world
      puts "hello world!"
    end
    pry main:/home/john $ load ".pryrc"
    => true
    pry main:/home/john $ hello_world
    hello world!

We can also interpolate Ruby code into the shell. In the
example below we use the shell command `cat` on a random file from the
current directory and count the number of lines in that file with
`wc`:

    pry main:/home/john $ .cat #{Dir['*.*'].sample} | wc -l
    44

### Code Browsing

You can browse method source code with the `show-method` command. Nearly all Ruby methods (and some C methods, with the pry-doc
gem) can have their source viewed. Code that is longer than a page is
sent through a pager (such as less), and all code is properly syntax
highlighted (even C code).

The `show-method` command accepts two syntaxes, the typical ri
`Class#method` syntax and also simply the name of a method that's in
scope. You can optionally pass the `-l` option to show-method to
include line numbers in the output.

In the following example we will enter the `Pry` class, list the
instance methods beginning with 're' and display the source code for the `rep` method:

    pry(main)> cd Pry
    pry(Pry):1> ls -M --grep re
    Pry#methods: re  readline  refresh  rep  repl  repl_epilogue  repl_prologue  retrieve_line
    pry(Pry):1> show-method rep -l

    From: /home/john/ruby/projects/pry/lib/pry/pry_instance.rb @ line 143:
    Number of lines: 6

    143: def rep(target=TOPLEVEL_BINDING)
    144:   target = Pry.binding_for(target)
    145:   result = re(target)
    146:
    147:   show_result(result) if should_print?
    148: end

Note that we can also view C methods (from Ruby Core) using the
`pry-doc` plugin; we also show off the alternate syntax for
`show-method`:

    pry(main)> show-method Array#select

    From: array.c in Ruby Core (C Method):
    Number of lines: 15

    static VALUE
    rb_ary_select(VALUE ary)
    {
        VALUE result;
        long i;

        RETURN_ENUMERATOR(ary, 0, 0);
        result = rb_ary_new2(RARRAY_LEN(ary));
        for (i = 0; i < RARRAY_LEN(ary); i++) {
            if (RTEST(rb_yield(RARRAY_PTR(ary)[i]))) {
                rb_ary_push(result, rb_ary_elt(ary, i));
            }
        }
        return result;
    }

### Documentation Browsing

One use-case for Pry is to explore a program at run-time by `cd`-ing
in and out of objects and viewing and invoking methods. In the course
of exploring it may be useful to read the documentation for a
specific method that you come across. Like `show-method` the `show-doc` command supports
two syntaxes - the normal `ri` syntax as well as accepting the name of
any method that is currently in scope.

The Pry documentation system does not rely on pre-generated `rdoc` or
`ri`, instead it grabs the comments directly above the method on
demand. This results in speedier documentation retrieval and allows
the Pry system to retrieve documentation for methods that would not be
picked up by `rdoc`. Pry also has a basic understanding of both the
rdoc and yard formats and will attempt to syntax highlight the
documentation appropriately.

Nonetheless, the `ri` functionality is very good and
has an advantage over Pry's system in that it allows documentation
lookup for classes as well as methods. Pry therefore has good
integration with  `ri` through the `ri` command. The syntax
for the command is exactly as it would be in command-line -
so it is not necessary to quote strings.

In our example we will enter the `Gem` class and view the
documentation for the `try_activate` method:

    pry(main)> cd Gem
    pry(Gem):1> show-doc try_activate

    From: /Users/john/.rvm/rubies/ruby-1.9.2-p180/lib/ruby/site_ruby/1.9.1/rubygems.rb @ line 201:
    Number of lines: 3

    Try to activate a gem containing path. Returns true if
    activation succeeded or wasn't needed because it was already
    activated. Returns false if it can't find the path in a gem.
    pry(Gem):1>

We can also use `ri` in the normal way:

    pry(main) ri Array#each
    ----------------------------------------------------------- Array#each
         array.each {|item| block }   ->   array
    ------------------------------------------------------------------------
         Calls _block_ once for each element in _self_, passing that element
         as a parameter.

            a = [ "a", "b", "c" ]
            a.each {|x| print x, " -- " }

         produces:

            a -- b -- c --

### Gist integration

If the `gist` gem is installed then method source or documentation can be gisted to GitHub with the
`gist` command.  The `gist` command is capable of gisting [almost any REPL content](https://gist.github.com/cae143e4533416529726), including methods, documentation,
input expressions, command source, and so on. In the example below we will gist the C source
code for the `Symbol#to_proc` method to GitHub:

    pry(main)> gist -m Symbol#to_proc
    Gist created at https://gist.github.com/5332c38afc46d902ce46 and added to clipboard.
    pry(main)>

You can see the actual gist generated here: [https://gist.github.com/5332c38afc46d902ce46](https://gist.github.com/5332c38afc46d902ce46)

### Edit methods

You can use `edit Class#method` or `edit my_method`
(if the method is in scope) to open a method for editing directly in
your favorite editor. Pry has knowledge of a few different editors and
will attempt to open the file at the line the method is defined.

You can set the editor to use by assigning to the `Pry.editor`
accessor. `Pry.editor` will default to `$EDITOR` or failing that will
use `nano` as the backup default. The file that is edited will be
automatically reloaded after exiting the editor - reloading can be
suppressed by passing the `--no-reload` option to `edit`

In the example below we will set our default editor to "emacsclient"
and open the `Pry#repl` method for editing:

    pry(main)> Pry.editor = "emacsclient"
    pry(main)> edit Pry#repl

### Live Help System

Many other commands are available in Pry; to see the full list type
`help` at the prompt. A short description of each command is provided
with basic instructions for use; some commands have a more extensive
help that can be accessed via typing `command_name --help`. A command
will typically say in its description if the `--help` option is
available.

### Use Pry as your Rails Console

The recommended way to use Pry as your Rails console is to add
[the `pry-rails` gem](https://github.com/rweng/pry-rails) to
your Gemfile. This replaces the default console with Pry, in
addition to loading the Rails console helpers and adding some
useful Rails-specific commands.

If you don't want to change your Gemfile, you can still run a Pry
console in your app's environment using Pry's `-r` flag:

    pry -r ./config/environment

Also check out the [wiki](https://github.com/pry/pry/wiki/Setting-up-Rails-or-Heroku-to-use-Pry)
for more information about integrating Pry with Rails.

### Limitations:

* Tab completion is currently a bit broken/limited this will have a
  major overhaul in a future version.

### Syntax Highlighting

Syntax highlighting is on by default in Pry. If you want to change
the colors, check out the [pry-theme](https://github.com/kyrylo/pry-theme)
gem.

You can toggle the syntax highlighting on and off in a session by
using the `toggle-color` command. Alternatively, you can turn it off
permanently by putting the line `Pry.color = false` in your `~/.pryrc`
file.

### Future Directions

Many new features are planned such as:

* Increase modularity (rely more on plugin system)
* Much improved documentation system, better support for YARD
* Better support for code and method reloading and saving code
* Extended and more sophisticated command system, allowing piping
between commands and running commands in background

### Contact

Problems or questions? File an issue at [GitHub](https://github.com/pry/pry/issues).

### Contributors

Pry is primarily the work of [John Mair (banisterfiend)](https://github.com/banister), for full list
of contributors see the
[CONTRIBUTORS](https://github.com/pry/pry/blob/master/CONTRIBUTORS) file.
