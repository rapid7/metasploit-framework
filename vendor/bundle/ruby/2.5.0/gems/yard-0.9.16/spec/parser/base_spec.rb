# frozen_string_literal: true

RSpec.describe YARD::Parser::Base do
  describe "#initialize" do
    class MyParser < Parser::Base; def initialize(a, b) end end

    it "takes 2 arguments" do
      expect { YARD::Parser::Base.new }.to raise_error(ArgumentError,
        /wrong (number|#) of arguments|given 0, expected 2/)
    end

    it "raises NotImplementedError on #initialize" do
      expect { YARD::Parser::Base.new('a', 'b') }.to raise_error(NotImplementedError)
    end

    it "raises NotImplementedError on #parse" do
      expect { MyParser.new('a', 'b').parse }.to raise_error(NotImplementedError)
    end

    it "raises NotImplementedError on #tokenize" do
      expect { MyParser.new('a', 'b').tokenize }.to raise_error(NotImplementedError)
    end
  end
end
