Support
=======

Support for Treetop is provided through the mailing list you can join or browse here:
http://groups.google.com/group/treetop-dev 

Tutorial
========
Languages can be split into two components, their *syntax* and their *semantics*. It's your understanding of English syntax that tells you the stream of words "Sleep furiously green ideas colorless" is not a valid sentence. Semantics is deeper. Even if we rearrange the above sentence to be "Colorless green ideas sleep furiously", which is syntactically correct, it remains nonsensical on a semantic level. With Treetop, you'll be dealing with languages that are much simpler than English, but these basic concepts apply. Your programs will need to address both the syntax and the semantics of the languages they interpret.

Treetop equips you with powerful tools for each of these two aspects of interpreter writing. You'll describe the syntax of your language with a *parsing expression grammar*. From this description, Treetop will generate a Ruby parser that transforms streams of characters written into your language into *abstract syntax trees* representing their structure. You'll then describe the semantics of your language in Ruby by defining methods on the syntax trees the parser generates.

Parsing Expression Grammars, The Basics
=======================================
The first step in using Treetop is defining a grammar in a file with the `.treetop` extension. Here's a grammar that's useless because it's empty:
    
    # my_grammar.treetop
    grammar MyGrammar
    end

Next, you start filling your grammar with rules. Each rule associates a name with a parsing expression, like the following:

    # my_grammar.treetop
    # You can use a .tt extension instead if you wish
    grammar MyGrammar
      rule hello
        'hello chomsky'
      end
    end

The first rule becomes the *root* of the grammar, causing its expression to be matched when a parser for the grammar is fed a string. The above grammar can now be used in a Ruby program. Notice how a string matching the first rule parses successfully, but a second nonmatching string does not.

    # use_grammar.rb
    require 'rubygems'
    require 'treetop'
    Treetop.load 'my_grammar'
    # or just:
    # require 'my_grammar'                     # This works because Polyglot hooks "require" to find and load Treetop files
    
    parser = MyGrammarParser.new
    puts parser.parse('hello chomsky')         # => Treetop::Runtime::SyntaxNode
    puts parser.parse('silly generativists!')  # => nil

Users of *regular expressions* will find parsing expressions familiar. They share the same basic purpose, matching strings against patterns. However, parsing expressions can recognize a broader category of languages than their less expressive brethren. Before we get into demonstrating that, lets cover some basics. At first parsing expressions won't seem much different. Trust that they are.

Terminal Symbols
----------------
The expression in the grammar above is a terminal symbol. It will only match a string that matches it exactly. There are two other kinds of terminal symbols, which we'll revisit later. Terminals are called *atomic expressions* because they aren't composed of smaller expressions.

Ordered Choices
---------------
Ordered choices are *composite expressions*, which allow for any of several subexpressions to be matched. These should be familiar from regular expressions, but in parsing expressions, they are delimited by the `/` character. Its important to note that the choices are prioritized in the order they appear. If an earlier expression is matched, no subsequent expressions are tried. Here's an example:

    # my_grammar.treetop
    grammar MyGrammar
      rule hello
        'hello chomsky' / 'hello lambek'
      end
    end
    
    # fragment of use_grammar.rb
    puts parser.parse('hello chomsky')         # => Treetop::Runtime::SyntaxNode
    puts parser.parse('hello lambek')          # => Treetop::Runtime::SyntaxNode
    puts parser.parse('silly generativists!')  # => nil

Note that once a choice rule has matched the text using a particular alternative at a particular location in the input and hence has succeeded, that choice will never be reconsidered, even if the chosen alternative causes another rule to fail where a later alternative wouldn't have. It's always a later alternative, since the first to succeed is final - why keep looking when you've found what you wanted? This is a feature of PEG parsers that you need to understand if you're going to succeed in using Treetop. In order to memoize success and failures, such decisions cannot be reversed. Luckily Treetop provides a variety of clever ways you can tell it to avoid making the wrong decisions. But more on that later.

Sequences
---------
Sequences are composed of other parsing expressions separated by spaces. Using sequences, we can tighten up the above grammar.

    # my_grammar.treetop
    grammar MyGrammar
      rule hello
        'hello ' ('chomsky' / 'lambek')
      end
    end

Note the use of parentheses to override the default precedence rules, which bind sequences more tightly than choices.

Once the whole sequence has been matched, the result is memoized and the details of the match will not be reconsidered for that location in the input.

Nonterminal Symbols
-------------------
Here we leave regular expressions behind. Nonterminals allow expressions to refer to other expressions by name. A trivial use of this facility would allow us to make the above grammar more readable should the list of names grow longer.

    # my_grammar.treetop
    grammar MyGrammar
      rule hello
        'hello ' linguist
      end
      
      rule linguist
        'chomsky' / 'lambek' / 'jacobsen' / 'frege'
      end
    end

The true power of this facility, however, is unleashed when writing *recursive expressions*. Here is a self-referential expression that can match any number of open parentheses followed by any number of closed parentheses. This is theoretically impossible with regular expressions due to the *pumping lemma*.

    # parentheses.treetop
    grammar Parentheses
      rule parens
        '(' parens ')' / ''
      end
    end


The `parens` expression simply states that a `parens` is a set of parentheses surrounding another `parens` expression or, if that doesn't match, the empty string. If you are uncomfortable with recursion, its time to get comfortable, because it is the basis of language. Here's a tip: Don't try and imagine the parser circling round and round through the same rule. Instead, imagine the rule is *already* defined while you are defining it. If you imagine that `parens` already matches a string of matching parentheses, then its easy to think of `parens` as an open and closing parentheses around another set of matching parentheses, which conveniently, you happen to be defining. You know that `parens` is supposed to represent a string of matched parentheses, so trust in that meaning, even if you haven't fully implemented it yet.

Repetition
----------
Any item in a rule may be followed by a '+' or a '*' character, signifying one-or-more and zero-or-more occurrences of that item. Beware though; the match is greedy, and if it matches too many items and causes subsequent items in the sequence to fail, the number matched will never be reconsidered. Here's a simple example of a rule that will never succeed:

    # toogreedy.treetop
    grammar TooGreedy
      rule a_s
      	'a'* 'a'
      end
    end

The 'a'* will always eat up any 'a's that follow, and the subsequent 'a' will find none there, so the whole rule will fail. You might need to use lookahead to avoid matching too much. Alternatively, you can use an occurrence range:

    # toogreedy.treetop
    grammar TooGreedy
      rule two_to_four_as
      	'a' 2..4
      end
    end

In an occurrence range, you may omit either the minimum count or the maximum count, so that "0.. " works like "*" and "1.. " works like '+'.

Negative Lookahead
------------------

When you need to ensure that the following item *doesn't* match in some case where it might otherwise, you can use negat!ve lookahead, which is an item preceeded by a ! - here's an example:

    # postcondition.treetop
    grammar PostCondition
      rule conditional_sentence
        ( !conditional_keyword word )+ conditional_keyword [ \t]+ word*
      end

      rule word
        ([a-zA-Z]+ [ \t]+) 
      end

      rule conditional_keyword
        'if' / 'while' / 'until'
      end
    end

Even though the rule `word` would match any of the conditional keywords, the first words of a conditional_sentence must not be conditional_keywords. The negative lookahead prevents that matching, and prevents the repetition from matching too much input. Note that the lookahead may be a grammar rule of any complexity, including one that isn't used elsewhere in your grammar.

Positive lookahead
------------------

Sometimes you want an item to match, but only if the *following* text would match some pattern. You don't want to consume that following text, but if it's not there, you want this rule to fail. You can append a positive lookahead like this to a rule by appending the lookahead rule preceeded by an & character.

Semantic predicates
-------------------

Warning: This is an advanced feature. You need to understand the way a packrat parser operates to use it correctly. The result of computing a rule containing a semantic predicate will be memoized, even if the same rule, applied later at the same location in the input, would work differently due to a semantic predicate returning a different value. If you don't understand the previous sentence yet still use this feature, you're on your own, so test carefully!

Sometimes, you need to run external Ruby code to decide whether this syntax rule should continue or should fail. You can do this using either positive or negative semantic predicates. These are Ruby code blocks (lambdas) which are called when the parser reaches that location. For this rule to succeed, the value must be true for a positive predicate (a block like &{ ... }), or false for a negative predicate (a block like !{ ... }).

The block is called with one argument, the array containing the preceding syntax nodes in the current sequence. Within the block, you cannot use node names or labels for the preceding nodes, as the node for the current rule does not yet exist. You must refer to preceding nodes using their position in the sequence.

    grammar Keywords
      rule sequence_of_reserved_and_nonreserved_words
      	( reserved / word )*
      end

      rule reserved
        word &{ |s| symbol_reserved?(s[0].text_value) }
      end

      rule word
        ([a-zA-Z]+ [ \t]+) 
      end
    end

One case where it is always safe to use a semantic predicate is to invoke the Ruby debugger, but don't forget to return true so the rule succeeds! Assuming you have required the 'ruby-debug' module somewhere, it looks like this:

      rule problems
        word &{ |s| debugger; true }
      end

When the debugger stops here, you can inspect the contents of the SyntaxNode for "word" by looking at s[0], and the stack trace will show how you got there.
