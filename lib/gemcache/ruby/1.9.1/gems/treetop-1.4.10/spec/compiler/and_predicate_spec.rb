require 'spec_helper'

module AndPredicateSpec
  describe "An &-predicated terminal symbol" do
    testing_expression '&"foo"'

    it "successfully parses input matching the terminal symbol, returning an epsilon syntax node" do
      parse('foo', :consume_all_input => false) do |result|
        result.should_not be_nil
        result.interval.should == (0...0)
      end
    end
  end

  describe "A sequence of a terminal and an and another &-predicated terminal" do
    testing_expression '"foo" &"bar"'

    it "matches input matching both terminals, but only consumes the first" do
      parse('foobar', :consume_all_input => false) do |result|
        result.should_not be_nil
        result.text_value.should == 'foo'
      end
    end
  
    it "fails to parse input matching only the first terminal, with a terminal failure recorded at index 3" do
      parse('foo') do |result|
        result.should be_nil
        terminal_failures = parser.terminal_failures
        terminal_failures.size.should == 1
        failure = terminal_failures[0]
        failure.index.should == 3
        failure.expected_string.should == 'bar'
      end
    end
  end
end
