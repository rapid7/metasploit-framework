require 'spec_helper'

module ParsingRuleSpec
  describe "a grammar with one parsing rule" do

    testing_grammar %{
      grammar Foo
        rule bar
          "baz"
        end
      end
    }

    it "stores and retrieves nodes in its node cache" do
      parser = self.class.const_get(:FooParser).new
      parser.send(:prepare_to_parse, 'baz')
      node_cache = parser.send(:node_cache)
    
      node_cache[:bar][0].should be_nil
    
      parser._nt_bar
    
      cached_node = node_cache[:bar][0]        
      cached_node.should be_an_instance_of(Runtime::SyntaxNode)
      cached_node.text_value.should == 'baz'
    
      parser.instance_eval { @index = 0 }
      parser._nt_bar.should equal(cached_node)
      parser.index.should == cached_node.interval.end
    end
  end
  
  
  describe "a grammar with choice that uses the cache and has a subsequent expression" do    
    testing_grammar %{
      grammar Logic
        rule expression
          value_plus
          /
          value
        end

        rule value_plus
          value "something else"
        end

        rule value
          [a-z]
          /
          "foobar" # the subsequent expression that needs cached.interval.end
        end
      end
    }
    
    it "parses a single-character value and generates a node from the cache" do
      result = parse('a')
      result.should be_a(Treetop::Runtime::SyntaxNode)
      result.elements.should be_nil
    end
  end
end
