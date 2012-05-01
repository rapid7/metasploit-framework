require 'spec_helper'

module ChoiceSpec
  describe "A choice between terminal symbols" do
    testing_expression '"foo" { def foo_method; end } / "bar" { def bar_method; end } / "baz" { def baz_method; end }'

    it "successfully parses input matching any of the alternatives, returning a node that responds to methods defined in its respective inline module" do
      result = parse('foo')
      result.should_not be_nil
      result.should respond_to(:foo_method)
    
      result = parse('bar')
      result.should_not be_nil
      result.should respond_to(:bar_method)
    
      result = parse('baz')
      result.should_not be_nil
      result.should respond_to(:baz_method)
    end
  
    it "upon parsing a string matching the second alternative, records the failure of the first terminal" do
      result = parse('bar')
      terminal_failures = parser.terminal_failures
      terminal_failures.size.should == 1
      failure = terminal_failures[0]
      failure.expected_string.should == 'foo'
      failure.index.should == 0
    end
  
    it "upon parsing a string matching the third alternative, records the failure of the first two terminals" do
      result = parse('baz')
      
      terminal_failures = parser.terminal_failures
      
      terminal_failures.size.should == 2

      failure_1 = terminal_failures[0]
      failure_1.expected_string == 'foo'
      failure_1.index.should == 0
    
      failure_2 = terminal_failures[1]
      failure_2.expected_string == 'bar'
      failure_2.index.should == 0
    end
  end

  describe "A choice between sequences" do
    testing_expression "'foo' 'bar' 'baz'\n/\n'bing' 'bang' 'boom'"

    it "successfully parses input matching any of the alternatives" do
      parse('foobarbaz').should_not be_nil
      parse('bingbangboom').should_not be_nil
    end
  end

  describe "A choice between terminals followed by a block" do  
    testing_expression "('a'/ 'b' / 'c') { def a_method; end }"

    it "extends a match of any of its subexpressions with a module created from the block" do
      ['a', 'b', 'c'].each do |letter|
        parse(letter).should respond_to(:a_method)
      end
    end
  end

  module TestModule
    def a_method
    end
  end

  describe "a choice followed by a declared module" do  
    testing_expression "('a'/ 'b' / 'c') <ChoiceSpec::TestModule>"

    it "extends a match of any of its subexpressions with a module created from the block" do
      ['a', 'b', 'c'].each do |letter|
        parse(letter).should respond_to(:a_method)
      end
    end
  end
end
