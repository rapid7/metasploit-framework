require 'spec_helper'

module SemanticPredicateSpec
  describe "An &-predicate block" do
    testing_expression '& {|| $ok_to_succeed}'

    it "succeeds if it returns true, returning an epsilon syntax node" do
      $ok_to_succeed = true
      parse('foo', :consume_all_input => false) do |result|
        result.should_not be_nil
        result.interval.should == (0...0)
      end
    end

    it "fails if it returns false" do
      $ok_to_succeed = false
      parse('foo', :consume_all_input => false) do |result|
        result.should be_nil
        terminal_failures = parser.terminal_failures
        terminal_failures.size.should == 0
      end
    end

  end

  describe "A sequence of a terminal and an &-predicate block" do
    testing_expression '"prior " &{|s| $value = s[0].text_value; $ok_to_succeed }'

    it "matches the input terminal and consumes it if the block returns true, seeing the terminal in the sequence" do
      $ok_to_succeed = true
      $value = nil
      parse('prior foo', :consume_all_input => false) do |result|
        result.should_not be_nil
        result.elements[0].text_value.should == "prior "
        result.text_value.should == 'prior '
        $value.should == 'prior '
      end
    end

    it "fails if the block returns false, but sees the terminal in the sequence" do
      $ok_to_succeed = false
      $value = nil
      parse('prior foo', :consume_all_input => false) do |result|
        result.should be_nil
        $value.should == 'prior '
        terminal_failures = parser.terminal_failures
        terminal_failures.size.should == 0
      end
    end

  end

  describe "A sequence of an optional terminal and an &-predicate block" do
    testing_expression '"prior "? &{|s| $value = s[0].text_value; $ok_to_succeed}'

    it "matches the input terminal and consumes it if the block returns true" do
      $ok_to_succeed = true
      parse('prior foo', :consume_all_input => false) do |result|
        result.should_not be_nil
        result.elements[0].text_value.should == "prior "
        result.text_value.should == 'prior '
        $value.should == 'prior '
      end
    end

    it "fails with no terminal_failures if the block returns false" do
      $ok_to_succeed = false
      parse('prior foo', :consume_all_input => false) do |result|
        result.should be_nil
        $value.should == 'prior '
        terminal_failures = parser.terminal_failures
        terminal_failures.size.should == 0
      end
    end

    it "fail and return the expected optional preceeding terminal as expected input if the block returns false" do
      $ok_to_succeed = false
      parse('foo', :consume_all_input => false) do |result|
        result.should be_nil
        terminal_failures = parser.terminal_failures
        terminal_failures.size.should == 1
        failure = terminal_failures[0]
        failure.index.should == 0
        failure.expected_string.should == 'prior '
      end
    end

  end

  describe "A !-predicate block" do
    testing_expression '! {|| $ok_to_succeed}'

    it "succeeds if it returns false, returning an epsilon syntax node" do
      $ok_to_succeed = false
      parse('foo', :consume_all_input => false) do |result|
        result.should_not be_nil
        result.interval.should == (0...0)
      end
    end

    it "fails if it returns true" do
      $ok_to_succeed = true
      parse('foo', :consume_all_input => false) do |result|
        result.should be_nil
        terminal_failures = parser.terminal_failures
        terminal_failures.size.should == 0
      end
    end

  end

  describe "A sequence of a terminal and an !-predicate block" do
    testing_expression '"prior " !{|s| $value = s[0].text_value; $ok_to_succeed }'

    it "matches the input terminal and consumes it if the block returns false, seeing the terminal in the sequence" do
      $ok_to_succeed = false
      $value = nil
      parse('prior foo', :consume_all_input => false) do |result|
        result.should_not be_nil
        result.elements[0].text_value.should == "prior "
        result.text_value.should == 'prior '
        $value.should == 'prior '
      end
    end

    it "fails if the block returns true, but sees the terminal in the sequence" do
      $ok_to_succeed = true
      $value = nil
      parse('prior foo', :consume_all_input => false) do |result|
        result.should be_nil
        $value.should == 'prior '
        terminal_failures = parser.terminal_failures
        terminal_failures.size.should == 0
      end
    end

  end

  describe "A sequence of an optional terminal and an !-predicate block" do
    testing_expression '"prior "? !{|s| $value = s[0].text_value; $ok_to_succeed}'

    it "matches the input terminal and consumes it if the block returns false" do
      $ok_to_succeed = false
      parse('prior foo', :consume_all_input => false) do |result|
        result.should_not be_nil
        result.elements[0].text_value.should == "prior "
        result.text_value.should == 'prior '
        $value.should == 'prior '
      end
    end

    it "fails with no terminal_failures if the block returns true" do
      $ok_to_succeed = true
      parse('prior foo', :consume_all_input => false) do |result|
        result.should be_nil
        $value.should == 'prior '
        terminal_failures = parser.terminal_failures
        terminal_failures.size.should == 0
      end
    end

    it "fail and return the expected optional preceeding terminal as expected input if the block returns true" do
      $ok_to_succeed = true
      parse('foo', :consume_all_input => false) do |result|
        result.should be_nil
        terminal_failures = parser.terminal_failures
        terminal_failures.size.should == 1
        failure = terminal_failures[0]
        failure.index.should == 0
        failure.expected_string.should == 'prior '
      end
    end

  end
end
