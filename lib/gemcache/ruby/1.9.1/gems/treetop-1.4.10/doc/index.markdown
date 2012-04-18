<p class="intro_text">

Treetop is a language for describing languages. Combining the elegance of Ruby with cutting-edge <em>parsing expression grammars</em>, it helps you analyze syntax with revolutionary ease.

</p>

    sudo gem install treetop

#Intuitive Grammar Specifications
Parsing expression grammars (PEGs) are simple to write and easy to maintain. They are a simple but powerful generalization of regular expressions that are easier to work with than the LALR or LR-1 grammars of traditional parser generators. There's no need for a tokenization phase, and _lookahead assertions_ can be used for a limited degree of context-sensitivity. Here's an extremely simple Treetop grammar that matches a subset of arithmetic, respecting operator precedence:

    grammar Arithmetic
      rule additive
        multitive ( '+' multitive )*
      end

      rule multitive
        primary ( [*/%] primary )*
      end

      rule primary
        '(' additive ')' / number
      end

      rule number
        '-'? [1-9] [0-9]*
      end
    end


#Syntax-Oriented Programming
Rather than implementing semantic actions that construct parse trees, Treetop lets you define methods on trees that it constructs for you automatically. You can define these methods directly within the grammar...

    grammar Arithmetic
      rule additive
        multitive a:( '+' multitive )* {
          def value
            a.elements.inject(multitive.value) { |sum, e|
              sum+e.multitive.value
            }
          end
        }
      end

      # other rules below ...
    end

...or associate rules with classes of nodes you wish your parsers to instantiate upon matching a rule.

    grammar Arithmetic
      rule additive
        multitive ('+' multitive)* <AdditiveNode>
      end

      # other rules below ...
    end


#Reusable, Composable Language Descriptions
Because PEGs are closed under composition, Treetop grammars can be treated like Ruby modules. You can mix them into one another and override rules with access to the `super` keyword. You can break large grammars down into coherent units or make your language's syntax modular. This is especially useful if you want other programmers to be able to reuse your work.

    grammar RubyWithEmbeddedSQL
      include SQL

      rule string
        quote sql_expression quote / super
      end
    end


#Acknowledgements


<a href="http://pivotallabs.com"><img id="pivotal_logo" src="./images/pivotal.gif"></a>

First, thank you to my employer Rob Mee of <a href="http://pivotallabs.com"/>Pivotal Labs</a> for funding a substantial portion of Treetop's development. He gets it.


I'd also like to thank:

* Damon McCormick for several hours of pair programming.
* Nick Kallen for lots of well-considered feedback and a few afternoons of programming.
* Brian Takita for a night of pair programming.
* Eliot Miranda for urging me rewrite as a compiler right away rather than putting it off.
* Ryan Davis and Eric Hodel for hurting my code.
* Dav Yaginuma for kicking me into action on my idea.
* Bryan Ford for his seminal work on Packrat Parsers.
* The editors of Lambda the Ultimate, where I discovered parsing expression grammars.
