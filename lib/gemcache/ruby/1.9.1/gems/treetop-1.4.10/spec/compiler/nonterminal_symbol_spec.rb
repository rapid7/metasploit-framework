require 'spec_helper'

module NonterminalSymbolSpec
  describe "A nonterminal symbol followed by a block" do
    testing_expression 'foo { def a_method; end }'
  
    parser_class_under_test.class_eval do
      def _nt_foo
        '_nt_foo called'
      end
    end
  
    it "compiles to a method call, extending its results with the anonymous module for the block" do
      result = parse('')
      result.should == '_nt_foo called'
      result.should respond_to(:a_method)
    end
  end

  module TestModule
    def a_method
    end
  end

  describe "a non-terminal followed by a module declaration" do
    testing_expression 'foo <NonterminalSymbolSpec::TestModule>'
  
    parser_class_under_test.class_eval do
      def _nt_foo
        '_nt_foo called'
      end
    end
  
    it "compiles to a method call, extending its results with the anonymous module for the block" do
      result = parse('')
      result.should == '_nt_foo called'
      result.should respond_to(:a_method)
    end
  end
end
