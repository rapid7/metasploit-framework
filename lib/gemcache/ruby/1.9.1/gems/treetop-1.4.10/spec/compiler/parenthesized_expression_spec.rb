require 'spec_helper'

module ParenthesizedExpressionSpec
  describe "An unadorned expression inside of parentheses" do
    testing_expression '("foo")'
  
    it "should behave as normal" do
      parse('foo').should_not be_nil
    end
  end

  describe "A prefixed-expression inside of parentheses" do
    testing_expression '(!"foo")'
  
    it "should behave as normal" do
      parse('foo').should be_nil
    end
  end
end
