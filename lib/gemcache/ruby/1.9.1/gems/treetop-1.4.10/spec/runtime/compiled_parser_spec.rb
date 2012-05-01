require 'spec_helper'

module CompiledParserSpec
  describe Runtime::CompiledParser, "for a grammar with two rules" do
    attr_reader :parser

    testing_grammar %{
      grammar TwoRules
        rule a
          'a'
        end

        rule b
          'b'
        end
      end
    }

    before do
      @parser = parser_class_under_test.new
    end

    it "allows its root to be specified" do
      parser.parse('a').should_not be_nil
      parser.parse('b').should be_nil

      # Check that the temporary-override works:
      parser.parse('b', :root => :b).should_not be_nil
      parser.parse('a', :root => :b).should be_nil

      # Check that the temporary-override isn't sticky:
      parser.parse('a').should_not be_nil

      # Try a permanent override:
      parser.root = :b
      parser.parse('b').should_not be_nil
      parser.parse('a').should be_nil
    end

    it "allows the requirement that all input be consumed to be disabled" do
      parser.parse('ab').should be_nil

      # Try a temporary override, and check it's not sticky:
      result = parser.parse('ab', :consume_all_input => false)
      result.should_not be_nil
      result.interval.should == (0...1)
      parser.parse('ab').should be_nil

      # Now a permanent override:
      parser.consume_all_input = false
      result = parser.parse('ab')
      result.should_not be_nil
      result.interval.should == (0...1)
    end

    it "allows input to be parsed at a given index" do
      parser.parse('ba').should be_nil
      parser.parse('ba', :index => 1).should_not be_nil
      # Check that the index defaults again to zero:
      parser.parse('a').should_not be_nil

      result = parser.parse('ba', :consume_all_input => false, :index => 1)
      result.should_not be_nil
      result.interval.should == (1...2)
    end

  end

  describe Runtime::CompiledParser, "for a grammar with a choice between terminals" do
    attr_reader :parser

    testing_grammar %{
      grammar Choice
        rule choice
          'a' / 'b' / 'c'
        end
      end
    }

    before do
      @parser = parser_class_under_test.new
    end

    it "provides #failure_reason, #failure_column, and #failure_line when there is a parse failure" do
      parser.parse('z').should be_nil
      parser.failure_reason.should == "Expected one of a, b, c at line 1, column 1 (byte 1) after "
      parser.failure_line.should == 1
      parser.failure_column.should == 1
    end
  end

  describe Runtime::CompiledParser,  "#terminal_failures" do
    attr_reader:parser

    testing_grammar %{
      grammar SequenceOfTerminals
        rule foo
          'a' 'b' 'c'
        end
      end
    }

    before do
      @parser = parser_class_under_test.new
    end

    it "is reset between parses" do
      parser.parse('ac')
      terminal_failures = parser.terminal_failures
      terminal_failures.size.should == 1
      failure = terminal_failures.first
      failure.index.should == 1
      failure.expected_string.should == 'b'

      parser.parse('b')
      terminal_failures = parser.terminal_failures
      terminal_failures.size.should == 1
      failure = terminal_failures.first
      failure.index.should == 0
      failure.expected_string.should == 'a'
    end
  end
end
