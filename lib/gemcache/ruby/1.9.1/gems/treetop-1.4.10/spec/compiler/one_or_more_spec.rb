require 'spec_helper'

module OneOrMoreSpec
  class Foo < Treetop::Runtime::SyntaxNode
  end

  describe "one or more of a terminal symbol followed by a node class declaration and a block" do
    testing_expression '"foo"+ <OneOrMoreSpec::Foo> { def a_method; end }'

    it "fails to parse epsilon, reporting a failure" do
      parse('') do |result|
        result.should be_nil
        terminal_failures = parser.terminal_failures
        terminal_failures.size.should == 1
        failure = terminal_failures.first
        failure.index.should == 0
        failure.expected_string.should == 'foo'
      end
    end
  
    it "successfully parses two of that terminal in a row, returning an instance of the declared node class and reporting the failure the third parsing attempt" do
      parse("foofoo") do |result|
        result.should_not be_nil
        result.should be_an_instance_of(Foo)
        result.should respond_to(:a_method)
        
        terminal_failures = parser.terminal_failures
        terminal_failures.size.should == 1
        failure = terminal_failures.first
        failure.index.should == 6
        failure.expected_string.should == 'foo'
      end
    end
  end
end
