#Using Treetop Grammars in Ruby
##Using the Command Line Compiler
You can compile `.treetop` files into Ruby source code with the `tt` command line script. `tt` takes an list of files with a `.treetop` extension and compiles them into `.rb` files of the same name. You can then `require` these files like any other Ruby script. Alternately, you can supply just one `.treetop` file and a `-o` flag to name specify the name of the output file. Improvements to this compilation script are welcome.

    tt foo.treetop bar.treetop
    tt foo.treetop -o foogrammar.rb

##Loading A Grammar Directly
The Polyglot gem makes it possible to load `.treetop` or `.tt` files directly with `require`. This will invoke `Treetop.load`, which automatically compiles the grammar to Ruby and then evaluates the Ruby source. If you are getting errors in methods you define on the syntax tree, try using the command line compiler for better stack trace feedback. A better solution to this issue is in the works.

In order to use Polyglot dynamic loading of `.treetop` or `.tt` files though, you need to require the Polyglot gem before you require the Treetop gem as Treetop will only create hooks into Polyglot for the treetop files if Polyglot is already loaded.  So you need to use:

    require 'polyglot'
    require 'treetop'

in order to use Polyglot auto loading with Treetop in Ruby.

##Instantiating and Using Parsers
If a grammar by the name of `Foo` is defined, the compiled Ruby source will define a `FooParser` class.
To parse input, create an instance and call its `parse` method with a string.
The parser will return the syntax tree of the match or `nil` if there is a failure.
Note that by default, the parser will fail unless *all* input is consumed.

    Treetop.load "arithmetic"
    
    parser = ArithmeticParser.new
    if parser.parse('1+1')
      puts 'success'
    else
      puts 'failure'
    end

##Parser Options
A Treetop parser has several options you may set.
Some are settable permanently by methods on the parser, but all may be passed in as options to the `parse` method.

    parser = ArithmeticParser.new
    input = 'x = 2; y = x+3;'

    # Temporarily override an option:
    result1 = parser.parse(input, :consume_all_input => false)
    puts "consumed #{parser.index} characters"

    parser.consume_all_input = false
    result1 = parser.parse(input)
    puts "consumed #{parser.index} characters"

    # Continue the parse with the next character:
    result2 = parser.parse(input, :index => parser.index)

    # Parse, but match rule `variable` instead of the normal root rule:
    parser.parse(input, :root => :variable)
    parser.root = :variable	# Permanent setting

If you have a statement-oriented language, you can save memory by parsing just one statement at a time,
and discarding the parse tree after each statement.


##Learning From Failure
If a parse fails, it returns nil. In this case, you can ask the parser for an explanation.
The failure reasons include the terminal nodes which were tried at the furthermost point the parse reached.

    parser = ArithmeticParser.new
    result = parser.parse('4+=3')

    if !result
      puts parser.failure_reason
      puts parser.failure_line
      puts parser.failure_column
    end

    =>
    Expected one of (, - at line 1, column 3 (byte 3) after +
    1
    3


##Using Parse Results
Please don't try to walk down the syntax tree yourself, and please don't use the tree as your own convenient data structure.
It contains many more nodes than your application needs, often even more than one for every character of input.

    parser = ArithmeticParser.new
    p parser.parse('2+3')

    =>
    SyntaxNode+Additive1 offset=0, "2+3" (multitive):
      SyntaxNode+Multitive1 offset=0, "2" (primary):
        SyntaxNode+Number0 offset=0, "2":
          SyntaxNode offset=0, ""
          SyntaxNode offset=0, "2"
          SyntaxNode offset=1, ""
        SyntaxNode offset=1, ""
      SyntaxNode offset=1, "+3":
        SyntaxNode+Additive0 offset=1, "+3" (multitive):
          SyntaxNode offset=1, "+"
          SyntaxNode+Multitive1 offset=2, "3" (primary):
            SyntaxNode+Number0 offset=2, "3":
              SyntaxNode offset=2, ""
              SyntaxNode offset=2, "3"
              SyntaxNode offset=3, ""
            SyntaxNode offset=3, ""

Instead, add methods to the root rule which return the information you require in a sensible form.
Each rule can call its sub-rules, and this method of walking the syntax tree is much preferable to
attempting to walk it from the outside.
