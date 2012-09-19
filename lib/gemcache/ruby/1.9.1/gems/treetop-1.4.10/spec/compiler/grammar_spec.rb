require 'spec_helper'

module GrammarSpec
  module Bar
  end

  describe "a grammar" do
    testing_grammar %{
      grammar Foo
              # This comment should not cause a syntax error, nor should the following empty one
              #
        include GrammarSpec::Bar

        rule foo
          bar / baz
        end

        rule bar
          'bar' 'bar'
        end

        rule baz
          'baz' 'baz'
        end
      end
    }

    it "parses matching input" do
      parse('barbar').should_not be_nil
      parse('bazbaz').should_not be_nil
    end

    it "fails if it does not parse all input" do
      parse('barbarbazbaz').should be_nil
    end

    it "mixes in included modules" do
      self.class.const_get(:Foo).ancestors.should include(GrammarSpec::Bar)
    end
  end
end
