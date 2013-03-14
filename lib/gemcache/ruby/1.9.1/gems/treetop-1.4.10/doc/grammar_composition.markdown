#Grammar Composition
A unique property of parsing expression grammars is that they are _closed under composition_. This means that when you compose two grammars they yield another grammar that can be composed yet again. This is a radical departure from parsing frameworks require on lexical scanning, which makes compositionally impossible. Treetop's facilities for composition are built upon those of Ruby.

##The Mapping of Treetop Constructs to Ruby Constructs
When Treetop compiles a grammar definition, it produces a module and a class. The module contains methods implementing all of the rules defined in the grammar. The generated class is a subclass of Treetop::Runtime::CompiledParser and includes the module. For example:

    grammar Foo
      ...
    end
    
results in a Ruby module named `Foo` and a Ruby class named `FooParser` that `include`s the `Foo` module.

##Using Mixin Semantics to Compose Grammars
Because grammars are just modules, they can be mixed into one another. This enables grammars to share rules.

    grammar A
      rule a
        'a'
      end
    end
    
    grammar B
      include A
    
      rule ab
        a 'b'
      end
    end
    
Grammar `B` above references rule `a` defined in a separate grammar that it includes. Because module inclusion places modules in the ancestor chain, rules may also be overridden with the use of the `super` keyword accessing the overridden rule.

    grammar A
      rule a
        'a'
      end
    end

    grammar B
      include A

      rule a
        super / 'b'
      end
    end

Now rule `a` in grammar `B` matches either `'a'` or `'b'`.

##Motivation
Imagine a grammar for Ruby that took account of SQL queries embedded in strings within the language. That could be achieved by combining two existing grammars.

    grammar RubyPlusSQL
      include Ruby
      include SQL
      
      rule expression
        ruby_expression
      end
      
      rule ruby_string
        ruby_quote sql_expression ruby_quote / ruby_string
      end
    end
    
##Work to be Done
It has become clear that the include facility in grammars would be more useful if it had the ability to name prefix all rules from the included grammar to avoid collision. This is a planned but currently unimplemented feature.