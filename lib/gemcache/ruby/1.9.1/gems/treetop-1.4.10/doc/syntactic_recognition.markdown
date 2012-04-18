#Syntactic Recognition 
Treetop grammars are written in a custom language based on parsing expression grammars. Literature on the subject of <a href="http://en.wikipedia.org/wiki/Parsing_expression_grammar">parsing expression grammars</a> (PEGs) is useful in writing Treetop grammars.

PEGs have no separate lexical analyser (since the algorithm has the same time-complexity guarantees as the best lexical analysers) so all whitespace and other lexical niceties (like comments) must be explicitly handled in the grammar. A further benefit is that multiple PEG grammars may be seamlessly composed into a single parser.

#Grammar Structure
Treetop grammars look like this:

    require "my_stuff"

    grammar GrammarName
      include Module::Submodule

      rule rule_name
        ...
      end
      
      rule rule_name
        ...
      end
      
      ...
    end

The main keywords are:

* `grammar` : This introduces a new grammar. It is followed by a constant name to which the grammar will be bound when it is loaded.

* `include`: This causes the generated parser to include the referenced Ruby module (which may be another parser)

* `require`: This must be at the start of the file, and is passed through to the emitted Ruby grammar

* `rule` : This defines a parsing rule within the grammar. It is followed by a name by which this rule can be referenced within other rules. It is then followed by a parsing expression defining the rule.

A grammar may be surrounded by one or more nested `module` statements, which provides a namespace for the generated Ruby parser.

Treetop will emit a module called `GrammarName` and a parser class called `GrammarNameParser` (in the module namespace, if specified).

#Parsing Expressions
Each rule associates a name with a _parsing expression_. Parsing expressions are a generalization of vanilla regular expressions. Their key feature is the ability to reference other expressions in the grammar by name.

##Terminal Symbols
###Strings
Strings are surrounded in double or single quotes and must be matched exactly.

* `"foo"`
* `'foo'`
  
###Character Classes
Character classes are surrounded by brackets. Their semantics are identical to those used in Ruby's regular expressions.

* `[a-zA-Z]`
* `[0-9]`

###The Anything Symbol
The anything symbol is represented by a dot (`.`) and matches any single character.

###Ellipsis
An empty string matches at any position and consumes no input. It's useful when you wish to treat a single symbol as part of a sequence, for example when an alternate rule will be processed using shared code.

<pre>
    rule alts
      ( foo bar / baz '' )
      {
        def value
          elements.map{|e| e.text_value }
        end
      }
    end
</pre>

##Nonterminal Symbols
Nonterminal symbols are unquoted references to other named rules. They are equivalent to an inline substitution of the named expression.

    rule foo
      "the dog " bar
    end
    
    rule bar
      "jumped"
    end

The above grammar is equivalent to:

    rule foo
      "the dog jumped"
    end

##Ordered Choice
Parsers attempt to match ordered choices in left-to-right order, and stop after the first successful match.

    "foobar" / "foo" / "bar"
    
Note that if `"foo"` in the above expression came first, `"foobar"` would never be matched.
Note also that the above rule will match `"bar"` as a prefix of `"barbie"`.
Care is required when it's desired to match language keywords exactly.

##Sequences

Sequences are a space-separated list of parsing expressions. They have higher precedence than choices, so choices must be parenthesized to be used as the elements of a sequence. 

    "foo" "bar" ("baz" / "bop")

##Zero or More
Parsers will greedily match an expression zero or more times if it is followed by the star (`*`) symbol.

* `'foo'*` matches the empty string, `"foo"`, `"foofoo"`, etc.

##One or More
Parsers will greedily match an expression one or more times if it is followed by the plus (`+`) symbol.

* `'foo'+` does not match the empty string, but matches `"foo"`, `"foofoo"`, etc.

##Optional Expressions
An expression can be declared optional by following it with a question mark (`?`).

* `'foo'?` matches `"foo"` or the empty string.

##Repetition count
A generalised repetition count (minimum, maximum) is also available.

* `'foo' 2..` matches `'foo'` two or more times
* `'foo' 3..5` matches `'foo'` from three to five times
* `'foo' ..4` matches `'foo'` from zero to four times

##Lookahead Assertions
Lookahead assertions can be used to make parsing expressions context-sensitive.
The parser will look ahead into the buffer and attempt to match an expression without consuming input.

###Positive Lookahead Assertion
Preceding an expression with an ampersand `(&)` indicates that it must match, but no input will be consumed in the process of determining whether this is true.

* `"foo" &"bar"` matches `"foobar"` but only consumes up to the end `"foo"`. It will not match `"foobaz"`.

###Negative Lookahead Assertion
Preceding an expression with a bang `(!)` indicates that the expression must not match, but no input will be consumed in the process of determining whether this is true.

* `"foo" !"bar"` matches `"foobaz"` but only consumes up to the end `"foo"`. It will not match `"foobar"`.

Note that a lookahead assertion may be used on any rule, not just a string terminal.

    rule things
      thing (!(disallowed / ',') following)*
    end

Here's a common use case:

    rule word
      [a-zA-Z]+
    end

    rule conjunction
      primitive ('and' ' '+ primitive)*
    end

    rule primitive
      (!'and' word ' '+)*
    end

Here's the easiest way to handle C-style comments:

    rule c_comment
      '/*'
      (
        !'*/'
        (. / "\n")
      )*
      '*/'
    end

##Semantic predicates (positive and negative)
Sometimes you must execute Ruby code during parsing in order to decide how to proceed.
This is an advanced feature, and must be used with great care, because it can change the
way a Treetop parser backtracks in a way that breaks the parsing algorithm. See the
notes below on how to use this feature safely.

The code block is the body of a Ruby lambda block, and should return true or false, to cause this
parse rule to continue or fail (for positive sempreds), fail or continue (for negative sempreds).

* `&{ ... }` Evaluate the block and fail this rule if the result is false or nil
* `!{ ... }` Evaluate the block and fail this rule if the result is not false or nil

The lambda is passed a single argument which is the array of syntax nodes matched so far in the
current sequence. Note that because the current rule has not yet succeeded, no syntax node has
yet been constructed, and so the lambda block is being run in a context where the `names` of the
preceding rules (or as assigned by labels) are not available to access the sub-rules.

    rule id
      [a-zA-Z][a-zA-Z0-9]*
      {
        def is_reserved
          ReservedSymbols.include? text_value
        end
      }
    end
    
    rule foo_rule
      foo id &{|seq| seq[1].is_reserved } baz
    end

Match "foo id baz" only if `id.is_reserved`. Note that `id` cannot be referenced by name from `foo_rule`,
since that rule has not yet succeeded, but `id` has completed and so its added methods are available.

    rule test_it
      foo bar &{|s| debugger; true } baz
    end

Match `foo` then `bar`, stop to enter the debugger (make sure you have said `require "ruby-debug"` somewhere),
then continue by trying to match `baz`.

Treetop, like other PEG parsers, achieves its performance guarantee by remembering which rules it has
tried at which locations in the input, and what the result was. This process, called memoization,
requires that the rule would produce the same result (if run again) as it produced the first time when
the result was remembered. If you violate this principle in your semantic predicates, be prepared to
fight Cerberus before you're allowed out of Hades again.
