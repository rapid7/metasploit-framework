require 'spec_helper'

describe "An expression for braces surrounding zero or more letters followed by semicolons" do
  testing_expression "'{' ([a-z] ';')* '}'"
  
  it "parses matching input successfully" do
    parse('{a;b;c;}').should_not be_nil
  end
  
  it "fails to parse input with an expression that is missing a semicolon, reporting the terminal failure occurring at the maximum index" do
    parse('{a;b;c}') do |result|
      result.should be_nil
      
      terminal_failures = parser.terminal_failures
      terminal_failures.size.should == 1      
      failure = terminal_failures[0]
      failure.index.should == 6
      failure.expected_string.should == ';'
    end
  end
end
