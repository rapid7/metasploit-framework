= polyglot

* http://github.com/cjheath/polyglot

== DESCRIPTION:

Author:	    Clifford Heath, 2007

The Polyglot library allows a Ruby module to register a loader
for the file type associated with a filename extension, and it
augments 'require' to find and load matching files.

This supports the creation of DSLs having a syntax that is most
appropriate to their purpose, instead of abusing the Ruby syntax.

Files are sought using the normal Ruby search path.

== EXAMPLE:

In file rubyglot.rb, define and register a file type handler:

    require 'polyglot'

    class RubyglotLoader
      def self.load(filename, options = nil, &block)
	File.open(filename) {|file|
	  # Load the contents of file as Ruby code:
	  # Implement your parser here instead!
	  Kernel.eval(file.read)
	}
      end
    end

    Polyglot.register("rgl", RubyglotLoader)

In file test.rb:

    require 'rubyglot'	# Create my file type handler
    require 'hello'	# Can add extra options or even a block here
    puts "Ready to go"
    Hello.new

In file hello.rgl (this simple example uses Ruby code):

    puts "Initializing"
    class Hello
      def initialize()
	puts "Hello, world\n"
      end
    end

Run:

    $ ruby test.rb
    Initializing
    Ready to go
    Hello, world
    $

== INSTALL:

sudo gem install polyglot

== LICENSE:

(The MIT License)

Copyright (c) 2007 Clifford Heath

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
