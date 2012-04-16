#Semantic Interpretation
Lets use the below grammar as an example. It describes parentheses wrapping a single character to an arbitrary depth.

    grammar ParenLanguage
      rule parenthesized_letter
        '(' parenthesized_letter ')'
        /
        [a-z]
      end
    end

Matches:

* `'a'`
* `'(a)'`
* `'((a))'`
* etc.


Output from a parser for this grammar looks like this:

![Tree Returned By ParenLanguageParser](./images/paren_language_output.png)

This is a parse tree whose nodes are instances of `Treetop::Runtime::SyntaxNode`. What if we could define methods on these node objects? We would then have an object-oriented program whose structure corresponded to the structure of our language. Treetop provides two techniques for doing just this.

##Associating Methods with Node-Instantiating Expressions
Sequences and all types of terminals are node-instantiating expressions. When they match, they create instances of `Treetop::Runtime::SyntaxNode`. Methods can be added to these nodes in the following ways:

###Inline Method Definition
Methods can be added to the nodes instantiated by the successful match of an expression

    grammar ParenLanguage
      rule parenthesized_letter
        '(' parenthesized_letter ')' {
          def depth
            parenthesized_letter.depth + 1
          end
        }
        /
        [a-z] {
          def depth
            0
          end
        }
      end
    end

Note that each alternative expression is followed by a block containing a method definition. A `depth` method is defined on both expressions. The recursive `depth` method defined in the block following the first expression determines the depth of the nested parentheses and adds one to it. The base case is implemented in the block following the second expression; a single character has a depth of 0.


###Custom `SyntaxNode` Subclass Declarations
You can instruct the parser to instantiate a custom subclass of Treetop::Runtime::SyntaxNode for an expression by following it by the name of that class enclosed in angle brackets (`<>`). The above inline method definitions could have been moved out into a single class like so.

    # in .treetop file
    grammar ParenLanguage
      rule parenthesized_letter
        '(' parenthesized_letter ')' <ParenNode>
        /
        [a-z] <ParenNode>
      end
    end

    # in separate .rb file
    class ParenNode < Treetop::Runtime::SyntaxNode
      def depth
        if nonterminal?
          parenthesized_letter.depth + 1
        else
          0
        end
      end
    end

##Automatic Extension of Results
Nonterminal and ordered choice expressions do not instantiate new nodes, but rather pass through nodes that are instantiated by other expressions. They can extend nodes they propagate with anonymous or declared modules, using similar constructs used with expressions that instantiate their own syntax nodes.

###Extending a Propagated Node with an Anonymous Module
    rule parenthesized_letter
      ('(' parenthesized_letter ')' / [a-z]) {
        def depth
          if nonterminal?
            parenthesized_letter.depth + 1
          else
            0
          end
        end
      }
    end

The parenthesized choice above can result in a node matching either of the two choices. The node will be extended with methods defined in the subsequent block. Note that a choice must always be parenthesized to be associated with a following block, otherwise the block will apply to just the last alternative.

###Extending A Propagated Node with a Declared Module
    # in .treetop file
    rule parenthesized_letter
      ('(' parenthesized_letter ')' / [a-z]) <ParenNode>
    end
    
    # in separate .rb file
    module ParenNode
      def depth
        if nonterminal?
          parenthesized_letter.depth + 1
        else
          0
        end
      end
    end

Here the result is extended with the `ParenNode` module. Note the previous example for node-instantiating expressions, the constant in the declaration must be a module because the result is extended with it.

##Automatically-Defined Element Accessor Methods
###Default Accessors
Nodes instantiated upon the matching of sequences have methods automatically defined for any nonterminals in the sequence.

    rule abc
      a b c {
        def to_s
          a.to_s + b.to_s + c.to_s
        end
      }
    end

In the above code, the `to_s` method calls automatically-defined element accessors for the nodes returned by parsing nonterminals `a`, `b`, and `c`. 

###Labels
Subexpressions can be given an explicit label to have an element accessor method defined for them. This is useful in cases of ambiguity between two references to the same nonterminal or when you need to access an unnamed subexpression.

    rule labels
      first_letter:[a-z] rest_letters:(', ' letter:[a-z])* {
        def letters
          [first_letter] + rest_letters.elements.map do |comma_and_letter|
            comma_and_letter.letter
          end
        end
      }
    end

The above grammar uses label-derived accessors to determine the letters in a comma-delimited list of letters. The labeled expressions _could_ have been extracted to their own rules, but if they aren't used elsewhere, labels still enable them to be referenced by a name within the expression's methods.

###Overriding Element Accessors
The module containing automatically defined element accessor methods is an ancestor of the module in which you define your own methods, meaning you can override them with access to the `super` keyword. Here's an example of how this fact can improve the readability of the example above.

    rule labels
      first_letter:[a-z] rest_letters:(', ' letter:[a-z])* {
        def letters
          [first_letter] + rest_letters
        end
        
        def rest_letters
          super.elements.map { |comma_and_letter| comma_and_letter.letter }
        end
      }
    end


##Methods Available on `Treetop::Runtime::SyntaxNode`

<table>
  <tr>
    <td>
      <code>terminal?</code>
    </td>
    <td>
      Was this node produced by the matching of a terminal symbol?
    </td>
  </tr>
  <tr>
    <td>
      <code>nonterminal?</code>
    </td>
    <td>
      Was this node produced by the matching of a nonterminal symbol?
    </td>
  <tr>
    <td>
      <code>text_value</code>
    </td>
    <td>
      The substring of the input represented by this node.
    </td>
  <tr>
    <td>
      <code>elements</code>
    </td>
    <td>
      Available only on nonterminal nodes, returns the nodes parsed by the elements of the matched sequence.
    </td>
  <tr>
    <td>
      <code>input</code>
    </td>
    <td>
       The entire input string, which is useful mainly in conjunction with <code>interval</code>
    </td>
  <tr>
    <td>
      <code>interval</code>
    </td>
    <td>
       The Range of characters in <code>input</code> matched by this rule
    </td>
  <tr>
    <td>
      <code>empty?</code>
    </td>
    <td>
       returns true if this rule matched no characters of input
    </td>
  <tr>
    <td>
      <code>inspect</code>
    </td>
    <td>
       Handy-dandy method that returns an indented subtree dump of the syntax tree starting here.
       This dump includes, for each node, the offset and a snippet of the text this rule matched, and the names of mixin modules and the accessor and extension methods.
    </td>
  </tr>
</table>
