# frozen_string_literal: true

RSpec.describe YARD::Handlers::Ruby::Base, '#valid_handler?' do
  include YARD::Parser::Ruby
  YARD::Parser::Ruby::AstNode # rubocop:disable Lint/Void

  before do
    allow(Handlers::Ruby::Base).to receive(:inherited)
    @processor = Handlers::Processor.new(OpenStruct.new(:parser_type => :ruby))
  end

  after(:all) do
    Handlers::Base.clear_subclasses
  end

  def valid(handler, stmt)
    expect(@processor.find_handlers(stmt)).to include(handler)
  end

  def invalid(handler, stmt)
    expect(@processor.find_handlers(stmt)).not_to include(handler)
  end

  it "only handles Handlers inherited from Ruby::Base class" do
    class IgnoredHandler < Handlers::Base
      handles :list
    end
    class NotIgnoredHandler < Handlers::Ruby::Base
      handles :list
    end
    allow(Handlers::Base).to receive(:subclasses).and_return [IgnoredHandler, NotIgnoredHandler]
    expect(@processor.find_handlers(s)).to eq [NotIgnoredHandler]
  end

  it "handles string input (matches AstNode#source)" do
    class StringHandler < Handlers::Ruby::Base
      handles "x"
    end
    allow(Handlers::Base).to receive(:subclasses).and_return [StringHandler]
    ast = Parser::Ruby::RubyParser.parse("if x == 2 then true end").ast
    valid StringHandler, ast[0][0][0]
    invalid StringHandler, ast[0][1]
  end

  it "handles symbol input (matches AstNode#type)" do
    class SymbolHandler < Handlers::Ruby::Base
      handles :myNodeType
    end
    allow(Handlers::Base).to receive(:subclasses).and_return [SymbolHandler]
    valid SymbolHandler, s(:myNodeType, s(1, 2, 3))
    invalid SymbolHandler, s(:NOTmyNodeType, s(1, 2, 3))
  end

  it "handles regex input (matches AstNode#source)" do
    class RegexHandler < Handlers::Ruby::Base
      handles(/^if x ==/)
    end
    allow(Handlers::Base).to receive(:subclasses).and_return [RegexHandler]
    ast = Parser::Ruby::RubyParser.parse("if x == 2 then true end").ast
    valid RegexHandler, ast
    invalid RegexHandler, ast[0][1]
  end

  it "handles AstNode input (matches AST literally)" do
    class ASTHandler < Handlers::Ruby::Base
      handles s(:vcall, s(:ident, "hello_world"))
    end
    allow(Handlers::Base).to receive(:subclasses).and_return [ASTHandler]
    valid ASTHandler, s(:vcall, s(:ident, "hello_world"))
    invalid ASTHandler, s(:vcall, s(:ident, "NOTHELLOWORLD"))
  end

  it "handles #method_call(:methname) on a valid AST" do
    class MethCallHandler < Handlers::Ruby::Base
      handles method_call(:meth)
    end
    allow(Handlers::Base).to receive(:subclasses).and_return [MethCallHandler]
    ast = Parser::Ruby::RubyParser.parse(<<-"eof").ast
      meth                   # 0
      meth()                 # 1
      meth(1,2,3)            # 2
      meth 1,2,3             # 3
      NotMeth.meth           # 4
      NotMeth.meth { }       # 5
      NotMeth.meth do end    # 6
      NotMeth.meth 1, 2, 3   # 7
      NotMeth.meth(1, 2, 3)  # 8
      NotMeth                # 9
    eof
    (0..8).each do |i|
      valid MethCallHandler, ast[i]
    end
    invalid MethCallHandler, ast[9]
  end
end if HAVE_RIPPER
