# frozen_string_literal: true

RSpec.describe YARD::Templates::Helpers::MethodHelper do
  include YARD::Templates::Helpers::BaseHelper
  include YARD::Templates::Helpers::MethodHelper

  describe "#format_args" do
    it "displays keyword arguments" do
      params = [['a:', '1'], ['b:', '2'], ['**kwargs', nil]]
      YARD.parse_string 'def foo; end'
      allow(Registry.at('#foo')).to receive(:parameters) { params }
      expect(format_args(Registry.at('#foo'))).to eq '(a: 1, b: 2, **kwargs)'
    end

    it "does not show &blockarg if no @param tag and has @yield" do
      YARD.parse_string <<-'eof'
        # @yield blah
        def foo(&block); end
      eof
      expect(format_args(Registry.at('#foo'))).to eq ''
    end

    it "does not show &blockarg if no @param tag and has @yieldparam" do
      YARD.parse_string <<-'eof'
        # @yieldparam blah test
        def foo(&block); end
      eof
      expect(format_args(Registry.at('#foo'))).to eq ''
    end

    it "shows &blockarg if @param block is documented (even with @yield)" do
      YARD.parse_string <<-'eof'
        # @yield [a,b]
        # @yieldparam a test
        # @param block test
        def foo(&block) end
      eof
      expect(format_args(Registry.at('#foo'))).to eq '(&block)'
    end
  end

  describe "#format_block" do
    before { YARD::Registry.clear }

    it "shows block for method with yield" do
      YARD.parse_string <<-'eof'
        def foo; yield(a, b, c) end
      eof
      expect(format_block(Registry.at('#foo'))).to eq "{|a, b, c| ... }"
    end

    it "shows block for method with @yieldparam tags" do
      YARD.parse_string <<-'eof'
        # @yieldparam _self me!
        def foo; end
      eof
      expect(format_block(Registry.at('#foo'))).to eq "{|_self| ... }"
    end

    it "shows block for method with @yield but no types" do
      YARD.parse_string <<-'eof'
        # @yield blah
        # @yieldparam a
        def foo; end

        # @yield blah
        def foo2; end
      eof
      expect(format_block(Registry.at('#foo'))).to eq "{|a| ... }"
      expect(format_block(Registry.at('#foo2'))).to eq "{ ... }"
    end

    it "shows block for method with @yield and types" do
      YARD.parse_string <<-'eof'
        # @yield [a, b, c] blah
        # @yieldparam a
        def foo; end
      eof
      expect(format_block(Registry.at('#foo'))).to eq "{|a, b, c| ... }"
    end
  end

  describe "#format_constant" do
    include YARD::Templates::Helpers::HtmlHelper

    it "displays correctly constant values which are quoted symbols" do
      YARD.parse_string %(
        class TestFmtConst
          Foo = :''
          Bar = :BAR
          Baz = :'B+z'
        end
      )
      # html_syntax_highlight will be called by format_constant for
      # Foo, Bar and Baz and in turn will enquire for options.highlight
      expect(self).to receive(:options).exactly(3).times.and_return(
        Options.new.update(:highlight => false)
      )
      foo, bar, baz = %w(Foo Bar Baz).map do |c|
        Registry.at("TestFmtConst::#{c}").value
      end
      expect(format_constant(foo)).to eq ":&quot;&quot;"
      expect(format_constant(bar)).to eq ':BAR'
      expect(format_constant(baz)).to eq ":&quot;B+z&quot;"
    end
  end
end
