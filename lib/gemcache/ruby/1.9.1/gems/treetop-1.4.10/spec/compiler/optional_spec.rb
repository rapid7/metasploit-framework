require 'spec_helper'

module OptionalSpec
  describe "An optional terminal symbol" do
    testing_expression '"foo"?'
  
    it "parses input matching the terminal" do
      parse('foo').should_not be_nil
    end
  
    it "parses epsilon, recording a failure" do
      parse('') do |result|
        result.should_not be_nil
        result.interval.should == (0...0)
        
        terminal_failures = parser.terminal_failures
        terminal_failures.size.should == 1
        failure = terminal_failures.first
        failure.index.should == 0
        failure.expected_string.should == 'foo'
      end
    end
  
    it "parses input not matching the terminal, returning an epsilon result and recording a failure" do
      parse('bar', :consume_all_input => false) do |result|
        result.should_not be_nil
        result.interval.should == (0...0)
        
        terminal_failures = parser.terminal_failures
        terminal_failures.size.should == 1
        failure = terminal_failures.first
        failure.index.should == 0
        failure.expected_string.should == 'foo'
      end
    end
  end
end
