# frozen_string_literal: true

RSpec.describe YARD::Templates::Helpers::HtmlSyntaxHighlightHelper do
  include YARD::Templates::Helpers::HtmlHelper
  include YARD::Templates::Helpers::HtmlSyntaxHighlightHelper

  describe "#html_syntax_highlight" do
    let(:object) { CodeObjects::NamespaceObject.new(:root, :YARD) }

    before do
      Registry.root.source_type = :ruby
    end

    it "does not highlight source if options.highlight is false" do
      expect(self).to receive(:options).and_return(Options.new.update(:highlight => false))
      expect(html_syntax_highlight("def x\nend")).to eq "def x\nend"
    end

    it "highlights source (legacy)" do
      type = Parser::SourceParser.parser_type
      Parser::SourceParser.parser_type = :ruby18
      expect(self).to receive(:options).and_return(Options.new.update(:highlight => true))
      expect = "<span class='rubyid_def def kw'>def</span><span class='rubyid_x identifier id'>x</span>
        <span class='string val'>'x'</span><span class='plus op'>+</span>
        <span class='regexp val'>/x/i</span><span class='rubyid_end end kw'>end</span>"
      result = html_syntax_highlight("def x\n  'x' + /x/i\nend")
      html_equals_string(result, expect)
      Parser::SourceParser.parser_type = type
    end

    it "highlights source (ripper)" do
      expect(self).to receive(:options).and_return(Options.new.update(:highlight => true))
      Parser::SourceParser.parser_type = :ruby
      expect = "<span class='kw'>def</span> <span class='id identifier rubyid_x'>x</span>
        <span class='tstring'><span class='tstring_beg'>'</span>
        <span class='tstring_content'>x</span><span class='tstring_end'>'</span>
        </span> <span class='op'>+</span> <span class='tstring'>
        <span class='regexp_beg'>/</span><span class='tstring_content'>x</span>
        <span class='regexp_end'>/i</span></span>\n<span class='kw'>end</span>"
      result = html_syntax_highlight("def x\n  'x' + /x/i\nend")
      html_equals_string(result, expect)
    end if HAVE_RIPPER

    it "returns escaped unhighlighted source if a syntax error is found (ripper)" do
      allow(self).to receive(:options).and_return(Options.new.update(:highlight => true))
      expect(html_syntax_highlight("def &x; ... end")).to eq "def &amp;x; ... end"
    end if HAVE_RIPPER

    it "returns escaped unhighlighted source if a syntax error is found (ripper)" do
      allow(self).to receive(:options).and_return(Options.new.update(:highlight => true))
      expect(html_syntax_highlight("$ git clone http://url")).to eq "$ git clone http://url"
    end if HAVE_RIPPER

    it "links constants/methods" do
      other = CodeObjects::NamespaceObject.new(:root, :Other)
      allow(self).to receive(:options).and_return(Options.new.update(:highlight => true))
      allow(self).to receive(:run_verifier).with([other]).and_return([other])
      allow(self).to receive(:link_object).with(other, "Other").and_return("LINK!")
      result = html_syntax_highlight("def x; Other end")
      html_equals_string(result, "<span class='kw'>def</span>
        <span class='id identifier rubyid_x'>x</span><span class='semicolon'>;</span>
        <span class='const'>LINK!</span> <span class='kw'>end</span>")
    end if HAVE_RIPPER
  end
end
