require 'spec_helper'

module AnythingSymbolSpec
  class Foo < Treetop::Runtime::SyntaxNode
  end

  describe "an anything symbol followed by a node class declaration and a block" do
    testing_expression '. <AnythingSymbolSpec::Foo> { def a_method; end }'
  
    it "matches any single character in a big range, returning an instance of the declared node class that responds to methods defined in the inline module" do
      (33..127).each do |digit|
        parse(digit.chr) do |result|
          result.should_not be_nil
          result.should be_an_instance_of(Foo)
          result.should respond_to(:a_method)
          result.interval.should == (0...1)
        end
      end
    end
  
    it "fails to parse epsilon" do
      parse('').should be_nil
    end
  end
    
  module ModFoo
  end

  describe "an anything symbol followed by a module declaration and a block" do
    testing_expression '. <AnythingSymbolSpec::ModFoo> { def a_method; end }'
  
    it "matches any single character in a big range, returning an instance of SyntaxNode extended by the declared module that responds to methods defined in the inline module" do
      (33..127).each do |digit|
        parse(digit.chr) do |result|
          result.should_not be_nil
          result.should be_an_instance_of(Treetop::Runtime::SyntaxNode)
          result.should be_a_kind_of(ModFoo)
          result.should respond_to(:a_method)
          result.interval.should == (0...1)
        end
      end
    end
  end
end
