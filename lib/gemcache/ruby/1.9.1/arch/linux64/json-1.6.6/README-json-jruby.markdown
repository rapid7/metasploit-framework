JSON-JRuby
==========

JSON-JRuby is a port of Florian Frank's native
[`json` library](http://json.rubyforge.org/) to JRuby.
It aims to be a perfect drop-in replacement for `json_pure`.


Development version
===================

The latest version is available from the
[Git repository](http://github.com/mernen/json-jruby/tree):

    git clone git://github.com/mernen/json-jruby.git


Compiling
=========

You'll need JRuby version 1.2 or greater to build JSON-JRuby.
Its path must be set on the `jruby.dir` property of
`nbproject/project.properties` (defaults to `../jruby`).

Additionally, you'll need [Ant](http://ant.apache.org/), and
[Ragel](http://www.cs.queensu.ca/~thurston/ragel/) 6.4 or greater.

Then, from the folder where the sources are located, type:

    ant clean jar

to clean any leftovers from previous builds and generate the `.jar` files.
To generate a RubyGem, specify the `gem` action rather than `jar`.
