# frozen_string_literal: true

include Parser::Ruby::Legacy

RSpec.describe YARD::Handlers::Ruby::Legacy::Base, "#handles and inheritance" do
  before do
    allow(Handlers::Ruby::Legacy::Base).to receive(:inherited)
    if RUBY_VERSION > '1.8.7'
      allow(Handlers::Ruby::Legacy::MixinHandler).to receive(:inherited) # fixes a Ruby1.9 issue
    end
    @processor = Handlers::Processor.new(OpenStruct.new(:parser_type => :ruby18))
  end

  after(:all) do
    Handlers::Base.clear_subclasses
  end

  def stmt(string)
    Statement.new(TokenList.new(string))
  end

  it "only handles Handlers inherited from Ruby::Legacy::Base class" do
    class IgnoredHandler < Handlers::Base
      handles "hello"
    end
    class NotIgnoredHandlerLegacy < Handlers::Ruby::Legacy::Base
      handles "hello"
    end
    allow(Handlers::Base).to receive(:subclasses).and_return [IgnoredHandler, NotIgnoredHandlerLegacy]
    expect(@processor.find_handlers(stmt("hello world"))).to eq [NotIgnoredHandlerLegacy]
  end

  it "handles a string input" do
    class TestStringHandler < Handlers::Ruby::Legacy::Base
      handles "hello"
    end

    expect(TestStringHandler.handles?(stmt("hello world"))).to be true
    expect(TestStringHandler.handles?(stmt("nothello world"))).to be false
  end

  it "handles regex input" do
    class TestRegexHandler < Handlers::Ruby::Legacy::Base
      handles(/^nothello$/)
    end

    expect(TestRegexHandler.handles?(stmt("nothello"))).to be true
    expect(TestRegexHandler.handles?(stmt("not hello hello"))).to be false
  end

  it "handles token input" do
    class TestTokenHandler < Handlers::Ruby::Legacy::Base
      handles TkMODULE
    end

    expect(TestTokenHandler.handles?(stmt("module"))).to be true
    expect(TestTokenHandler.handles?(stmt("if"))).to be false
  end

  it "parses a do/end or { } block with #parse_block" do
    class MyBlockHandler < Handlers::Ruby::Legacy::Base
      handles(/\AmyMethod\b/)
      def process
        parse_block(:owner => "test")
      end
    end

    class MyBlockInnerHandler < Handlers::Ruby::Legacy::Base
      handles "inner"
      def self.reset; @@reached = false end
      def self.reached?; @@reached ||= false end
      def process; @@reached = true end
    end

    allow(Handlers::Base).to receive(:subclasses).and_return [MyBlockHandler, MyBlockInnerHandler]
    Parser::SourceParser.parser_type = :ruby18
    Parser::SourceParser.parse_string "myMethod do inner end"
    expect(MyBlockInnerHandler).to be_reached
    MyBlockInnerHandler.reset
    Parser::SourceParser.parse_string "myMethod { inner }"
    expect(MyBlockInnerHandler).to be_reached
    Parser::SourceParser.parser_type = :ruby
  end
end
