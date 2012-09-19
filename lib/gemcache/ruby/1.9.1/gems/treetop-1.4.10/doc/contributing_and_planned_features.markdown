#Google Group
I've created a <a href="http://groups.google.com/group/treetop-dev">Google Group</a> as a better place to organize discussion and development.
treetop-dev@google-groups.com

#Contributing
Visit <a href="http://github.com/nathansobo/treetop/tree/master">the Treetop repository page on GitHub</a> in your browser for more information about checking out the source code.

I like to try Rubinius's policy regarding commit rights. If you submit one patch worth integrating, I'll give you commit rights. We'll see how this goes, but I think it's a good policy.

##Getting Started with the Code
Treetop compiler is interesting in that it is implemented in itself. Its functionality revolves around `metagrammar.treetop`, which specifies the grammar for Treetop grammars. I took a hybrid approach with regard to definition of methods on syntax nodes in the metagrammar. Methods that are more syntactic in nature, like those that provide access to elements of the syntax tree, are often defined inline, directly in the grammar. More semantic methods are defined in custom node classes.

Iterating on the metagrammar is tricky. The current testing strategy uses the last stable version of Treetop to parse the version under test. Then the version under test is used to parse and functionally test the various pieces of syntax it should recognize and translate to Ruby. As you change `metagrammar.treetop` and its associated node classes, note that the node classes you are changing are also used to support the previous stable version of the metagrammar, so must be kept backward compatible until such time as a new stable version can be produced to replace it.

##Tests
Most of the compiler's tests are functional in nature. The grammar under test is used to parse and compile piece of sample code. Then I attempt to parse input with the compiled output and test its results.

#What Needs to be Done
##Small Stuff
* Improve the `tt` command line tool to allow `.treetop` extensions to be elided in its arguments.
* Generate and load temp files with `Treetop.load` rather than evaluating strings to improve stack trace readability.
* Allow `do/end` style blocks as well as curly brace blocks. This was originally omitted because I thought it would be confusing. It probably isn't.

##Big Stuff
####Transient Expressions
Currently, every parsing expression instantiates a syntax node. This includes even very simple parsing expressions, like single characters. It is probably unnecessary for every single expression in the parse to correspond to its own syntax node, so much savings could be garnered from a transient declaration that instructs the parser only to attempt a match without instantiating nodes.

###Generate Rule Implementations in C
Parsing expressions are currently compiled into simple Ruby source code that comprises the body of parsing rules, which are translated into Ruby methods. The generator could produce C instead of Ruby in the body of these method implementations.

###Global Parsing State and Semantic Backtrack Triggering
Some programming language grammars are not entirely context-free, requiring that global state dictate the behavior of the parser in certain circumstances. Treetop does not currently expose explicit parser control to the grammar writer, and instead automatically constructs the syntax tree for them. A means of semantic parser control compatible with this approach would involve callback methods defined on parsing nodes. Each time a node is successfully parsed it will be given an opportunity to set global state and optionally trigger a parse failure on _extrasyntactic_ grounds. Nodes will probably need to define an additional method that undoes their changes to global state when there is a parse failure and they are backtracked.

Here is a sketch of the potential utility of such mechanisms. Consider the structure of YAML, which uses indentation to indicate block structure.

    level_1:
      level_2a:
      level_2b:
        level_3a:
      level_2c:    

Imagine a grammar like the following:

    rule yaml_element
      name ':' block
      /
      name ':' value
    end
    
    rule block
      indent yaml_elements outdent
    end

    rule yaml_elements
      yaml_element (samedent yaml_element)*
    end
    
    rule samedent
      newline spaces {
        def after_success(parser_state)
          spaces.length == parser_state.indent_level
        end
      }
    end
    
    rule indent
      newline spaces {
        def after_success(parser_state)
          if spaces.length == parser_state.indent_level + 2
            parser_state.indent_level += 2
            true
          else
            false # fail the parse on extrasyntactic grounds
          end
        end
      
        def undo_success(parser_state)
          parser_state.indent_level -= 2
        end
      }
    end
    
    rule outdent
      newline spaces {
        def after_success(parser_state)
          if spaces.length == parser_state.indent_level - 2
            parser_state.indent_level -= 2
            true
          else
            false # fail the parse on extrasyntactic grounds
          end
        end
      
        def undo_success(parser_state)
          parser_state.indent_level += 2
        end
      }
    end

In this case a block will be detected only if a change in indentation warrants it. Note that this change in the state of indentation must be undone if a subsequent failure causes this node not to ultimately be incorporated into a successful result.

I am by no means sure that the above sketch is free of problems, or even that this overall strategy is sound, but it seems like a promising path.
