# frozen_string_literal: true
require 'pp'
require 'stringio'

include YARD::Parser::Ruby

RSpec.describe YARD::Parser::Ruby::AstNode do
  describe "#jump" do
    it "jumps to the first specific inner node if found" do
      ast = s(:paren, s(:paren, s(:params, s(s(:ident, "hi"), s(:ident, "bye")))))
      expect(ast.jump(:params)[0][0].type).to equal(:ident)
    end

    it "returns the original ast if no inner node is found" do
      ast = s(:paren, s(:list, s(:list, s(s(:ident, "hi"), s(:ident, "bye")))))
      expect(ast.jump(:params).object_id).to eq ast.object_id
    end
  end

  describe "#pretty_print" do
    it "shows a list of nodes" do
      obj = YARD::Parser::Ruby::RubyParser.parse("# x\nbye", "x").ast
      out = StringIO.new
      PP.pp(obj, out)
      vcall = RUBY_VERSION >= '1.9.3' ? 'vcall' : 'var_ref'
      expect(out.string).to eq "s(s(:#{vcall},\n" \
                               "      s(:ident, \"bye\", line: 2..2, source: 4..6),\n" \
                               "      docstring: \"x\",\n" \
                               "      line: 2..2,\n" \
                               "      source: 4..6))\n"
    end
  end
end if HAVE_RIPPER
