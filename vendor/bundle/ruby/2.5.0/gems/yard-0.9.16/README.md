# YARD: Yay! A Ruby Documentation Tool

[![Homepage](http://img.shields.io/badge/home-yardoc.org-blue.svg)](http://yardoc.org)
[![GitHub](http://img.shields.io/badge/github-lsegal/yard-blue.svg)](http://github.com/lsegal/yard)
[![Documentation](http://img.shields.io/badge/docs-rdoc.info-blue.svg)](http://rubydoc.org/gems/yard/frames)

[![Gem Version](https://badge.fury.io/rb/yard.svg)](http://github.com/lsegal/yard/releases)
[![Build Status](https://travis-ci.org/lsegal/yard.svg?branch=master)](https://travis-ci.org/lsegal/yard)
[![Coverage Status](https://coveralls.io/repos/github/lsegal/yard/badge.svg)](https://coveralls.io/github/lsegal/yard)
[![License](http://img.shields.io/badge/license-MIT-yellowgreen.svg)](#license)

## Synopsis

YARD is a documentation generation tool for the Ruby programming language.
It enables the user to generate consistent, usable documentation that can be
exported to a number of formats very easily, and also supports extending for
custom Ruby constructs such as custom class level definitions. Below is a
summary of some of YARD's notable features.


## Feature List

**1. RDoc/SimpleMarkup Formatting Compatibility**: YARD is made to be compatible
with RDoc formatting. In fact, YARD does no processing on RDoc documentation
strings, and leaves this up to the output generation tool to decide how to
render the documentation.

**2. Yardoc Meta-tag Formatting Like Python, Java, Objective-C and other languages**:
YARD uses a '@tag' style definition syntax for meta tags alongside  regular code
documentation. These tags should be able to happily sit side by side RDoc formatted
documentation, but provide a much more consistent and usable way to describe
important information about objects, such as what parameters they take and what types
they are expected to be, what type a method should return, what exceptions it can
raise, if it is deprecated, etc.. It also allows information to be better (and more
consistently) organized during the output generation phase. You can find a list
of tags in the {file:docs/Tags.md#taglist Tags.md} file.

YARD also supports an optional "types" declarations for certain tags.
This allows the developer to document type signatures for ruby methods and
parameters in a non intrusive but helpful and consistent manner. Instead of
describing this data in the body of the description, a developer may formally
declare the parameter or return type(s) in a single line. Consider the
following method documented with YARD formatting:

```ruby
# Reverses the contents of a String or IO object.
#
# @param [String, #read] contents the contents to reverse
# @return [String] the contents reversed lexically
def reverse(contents)
  contents = contents.read if contents.respond_to? :read
  contents.reverse
end
```

With the above @param tag, we learn that the contents parameter can either be
a String or any object that responds to the 'read' method, which is more
powerful than the textual description, which says it should be an IO object.
This also informs the developer that they should expect to receive a String
object returned by the method, and although this may be obvious for a
'reverse' method, it becomes very useful when the method name may not be as
descriptive.

**3. Custom Constructs and Extensibility of YARD**: YARD is designed to be
extended and customized by plugins. Take for instance the scenario where you
need to document the following code:

```ruby
class List
 # Sets the publisher name for the list.
 cattr_accessor :publisher
end
```

This custom declaration provides dynamically generated code that is hard for a
documentation tool to properly document without help from the developer. To
ease the pains of manually documenting the procedure, YARD can be extended by
the developer to handle the `cattr_accessor` construct and automatically create
an attribute on the class with the associated documentation. This makes
documenting external API's, especially dynamic ones, a lot more consistent for
consumption by the users.

YARD is also designed for extensibility everywhere else, allowing you to add
support for new programming languages, new data structures and even where/how
data is stored.

**4. Raw Data Output**: YARD also outputs documented objects as raw data (the
dumped Namespace) which can be reloaded to do generation at a later date, or
even auditing on code. This means that any developer can use the raw data to
perform output generation for any custom format, such as YAML, for instance.
While YARD plans to support XHTML style documentation output as well as
command line (text based) and possibly XML, this may still be useful for those
who would like to reap the benefits of YARD's processing in other forms, such
as throwing all the documentation into a database. Another useful way of
exploiting this raw data format would be to write tools that can auto generate
test cases, for example, or show possible unhandled exceptions in code.

**5. Local Documentation Server**: YARD can serve documentation for projects
or installed gems (similar to `gem server`) with the added benefit of dynamic
searching, as well as live reloading. Using the live reload feature, you can
document your code and immediately preview the results by refreshing the page;
YARD will do all the work in re-generating the HTML. This makes writing
documentation a much faster process.


## Installing

To install YARD, use the following command:

```sh
$ gem install yard
```

(Add `sudo` if you're installing under a POSIX system as root)

Alternatively, if you've checked the source out directly, you can call
`rake install` from the root project directory.

**Important Note for Debian/Ubuntu users:** there's a possible chance your Ruby
install lacks RDoc, which is occasionally used by YARD to convert markup to HTML.
If running `which rdoc` turns up empty, install RDoc by issuing:

```sh
$ sudo apt-get install rdoc
```


## Usage

There are a couple of ways to use YARD. The first is via command-line, and the
second is the Rake task.

**1. yard Command-line Tool**

YARD comes packaged with a executable named `yard` which can control the many
functions of YARD, including generating documentation, graphs running the
YARD server, and so on. To view a list of available YARD commands, type:

```sh
$ yard --help
```

Plugins can also add commands to the `yard` executable to provide extra
functionality.

### Generating Documentation

<span class="note">The `yardoc` executable is a shortcut for `yard doc`.</span>

The most common command you will probably use is `yard doc`, or `yardoc`. You
can type `yardoc --help` to see the options that YARD provides, but the
easiest way to generate docs for your code is to simply type `yardoc` in your
project root. This will assume your files are
located in the `lib/` directory. If they are located elsewhere, you can specify
paths and globs from the commandline via:

```sh
$ yardoc 'lib/**/*.rb' 'app/**/*.rb' ...etc...
```

The tool will generate a `.yardoc` file which will store the cached database
of your source code and documentation. If you want to re-generate your docs
with another template you can simply use the `--use-cache` (or -c)
option to speed up the generation process by skipping source parsing.

YARD will by default only document code in your public visibility. You can
document your protected and private code by adding `--protected` or
`--private` to the option switches. In addition, you can add `--no-private`
to also ignore any object that has the `@private` meta-tag. This is similar
to RDoc's ":nodoc:" behaviour, though the distinction is important. RDoc
implies that the object with :nodoc: would not be documented, whereas
YARD still recommends documenting private objects for the private API (for
maintainer/developer consumption).

You can also add extra informative files (README, LICENSE) by separating
the globs and the filenames with '-'.

```sh
$ yardoc 'app/**/*.rb' - README LICENSE FAQ
```

If no globs precede the '-' argument, the default glob (`lib/**/*.rb`) is
used:

```sh
$ yardoc - README LICENSE FAQ
```

Note that the README file can be specified with its own `--readme` switch.

You can also add a `.yardopts` file to your project directory which lists
the switches separated by whitespace (newlines or space) to pass to yardoc
whenever it is run. A full overview of the `.yardopts` file can be found in
{YARD::CLI::Yardoc}.

### Queries

The `yardoc` tool also supports a `--query` argument to only include objects
that match a certain data or meta-data query. The query syntax is Ruby, though
a few shortcuts are available. For instance, to document only objects that have
an "@api" tag with the value "public", all of the following syntaxes would give
the same result:

```sh
--query '@api.text == "public"'
--query 'object.has_tag?(:api) && object.tag(:api).text == "public"'
--query 'has_tag?(:api) && tag(:api).text == "public"'
```

Note that the "@tag" syntax returns the first tag named "tag" on the object.
To return the array of all tags named "tag", use "@@tag".

Multiple `--query` arguments are allowed in the command line parameters. The
following two lines both check for the existence of a return and param tag:

```sh
--query '@return' --query '@param'
--query '@return && @param'
```

For more information about the query syntax, see the {YARD::Verifier} class.

**2. Rake Task**

The second most obvious is to generate docs via a Rake task. You can do this by
adding the following to your `Rakefile`:

```ruby
YARD::Rake::YardocTask.new do |t|
 t.files   = ['lib/**/*.rb', OTHER_PATHS]   # optional
 t.options = ['--any', '--extra', '--opts'] # optional
 t.stats_options = ['--list-undoc']         # optional
end
```

All the settings: `files`, `options` and `stats_options` are optional. `files` will default to
`lib/**/*.rb`, `options` will represents any options you might want
to add and `stats_options` will pass extra options to the stats command.
Again, a full list of options is available by typing `yardoc --help`
in a shell. You can also override the options at the Rake command-line with the
OPTS environment variable:

```sh
$ rake yard OPTS='--any --extra --opts'
```

**3. `yri` RI Implementation**

The yri binary will use the cached .yardoc database to give you quick ri-style
access to your documentation. It's way faster than ri but currently does not
work with the stdlib or core Ruby libraries, only the active project. Example:

```sh
$ yri YARD::Handlers::Base#register
$ yri File.relative_path
```

Note that class methods must not be referred to with the "::" namespace
separator. Only modules, classes and constants should use "::".

You can also do lookups on any installed gems. Just make sure to build the
.yardoc databases for installed gems with:

```sh
$ yard gems
```

If you don't have sudo access, it will write these files to your `~/.yard`
directory. `yri` will also cache lookups there.

**4. `yard server` Documentation Server**

The `yard server` command serves documentation for a local project or all installed
RubyGems. To serve documentation for a project you are working on, simply run:

```sh
$ yard server
```

And the project inside the current directory will be parsed (if the source has
not yet been scanned by YARD) and served at [http://localhost:8808](http://localhost:8808).

### Live Reloading

If you want to serve documentation on a project while you document it so that
you can preview the results, simply pass `--reload` (`-r`) to the above command
and YARD will reload any changed files on each request. This will allow you to
change any documentation in the source and refresh to see the new contents.

### Serving Gems

To serve documentation for all installed gems, call:

```sh
$ yard server --gems
```

This will also automatically build documentation for any gems that have not
been previously scanned. Note that in this case there will be a slight delay
between the first request of a newly parsed gem.


**5. `yard graph` Graphviz Generator**

You can use `yard graph` to generate dot graphs of your code. This, of course,
requires [Graphviz](http://www.graphviz.org) and the `dot` binary. By default
this will generate a graph of the classes and modules in the best UML2 notation
that Graphviz can support, but without any methods listed. With the `--full`
option, methods and attributes will be listed. There is also a `--dependencies`
option to show mixin inclusions. You can output to stdout or a file, or pipe directly
to `dot`. The same public, protected and private visibility rules apply to `yard graph`.
More options can be seen by typing `yard graph --help`, but here is an example:

```sh
$ yard graph --protected --full --dependencies
```


## Changelog

See {file:CHANGELOG.md} for a list of changes.

## License

YARD &copy; 2007-2018 by [Loren Segal](mailto:lsegal@soen.ca). YARD is
licensed under the MIT license except for some files which come from the
RDoc/Ruby distributions. Please see the {file:LICENSE} and {file:LEGAL}
documents for more information.
