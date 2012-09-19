require 'spec_helper'

module RepeatedSubruleSpec
  describe "a repeated subrule" do
    testing_grammar %{
      grammar Foo
        rule foo
          a:'a' space b:'b' space 'c'
        end

        rule space
          ' '
        end
      end
    }
  
    it "should produce a parser having sequence-numbered node accessor methods" do
      parse("a b c") do |result|
        result.should_not be_nil
        result.should respond_to(:space1)
        result.should respond_to(:space2)
        result.should_not respond_to(:space)
        result.should respond_to(:a)
        result.should respond_to(:b)
        result.should_not respond_to(:c)
      end
    end
  end
end
