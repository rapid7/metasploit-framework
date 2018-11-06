# frozen_string_literal: true
RSpec.shared_examples_for "signature" do
  before do
    YARD::Registry.clear
    @options = Templates::TemplateOptions.new
    @options.reset_defaults
    allow(self).to receive(:options).and_return(@options)
  end

  def trim(sig) sig.gsub(/\s+/, ' ') end

  it "shows signature for regular instance method" do
    YARD.parse_string "def foo; end"
    expect(trim(signature(Registry.at('#foo')))).to eq @results[:regular]
  end

  it "allows default return type to be changed" do
    @options.default_return = "Hello"
    YARD.parse_string "def foo; end"
    expect(trim(signature(Registry.at('#foo')))).to eq @results[:default_return]
  end

  it "allows default return type to be omitted" do
    @options.default_return = ""
    YARD.parse_string "def foo; end"
    expect(trim(signature(Registry.at('#foo')))).to eq @results[:no_default_return]
  end

  it "shows signature for private class method" do
    YARD.parse_string "class A; private; def self.foo; end end"
    expect(trim(signature(Registry.at('A.foo')))).to eq @results[:private_class]
  end

  it "shows return type for single type" do
    YARD.parse_string <<-'eof'
      # @return [String]
      def foo; end
    eof
    expect(trim(signature(Registry.at('#foo')))).to eq @results[:single]
  end

  it "shows return type for 2 types" do
    YARD.parse_string <<-'eof'
      # @return [String, Symbol]
      def foo; end
    eof
    expect(trim(signature(Registry.at('#foo')))).to eq @results[:two_types]
  end

  it "shows return type for 2 types over multiple tags" do
    YARD.parse_string <<-'eof'
      # @return [String]
      # @return [Symbol]
      def foo; end
    eof
    expect(trim(signature(Registry.at('#foo')))).to eq @results[:two_types_multitag]
  end

  it "shows 'Type?' if return types are [Type, nil]" do
    YARD.parse_string <<-'eof'
      # @return [Type, nil]
      def foo; end
    eof
    expect(trim(signature(Registry.at('#foo')))).to eq @results[:type_nil]
  end

  it "shows 'Type?' if return types are [Type, nil, nil] (extra nil)" do
    YARD.parse_string <<-'eof'
      # @return [Type, nil]
      # @return [nil]
      def foo; end
    eof
    expect(trim(signature(Registry.at('#foo')))).to eq @results[:type_nil]
  end

  it "shows 'Type+' if return types are [Type, Array<Type>]" do
    YARD.parse_string <<-'eof'
      # @return [Type, <Type>]
      def foo; end
    eof
    expect(trim(signature(Registry.at('#foo')))).to eq @results[:type_array]
  end

  it "shows (Type, ...) for more than 2 return types" do
    YARD.parse_string <<-'eof'
      # @return [Type, <Type>]
      # @return [AnotherType]
      def foo; end
    eof
    expect(trim(signature(Registry.at('#foo')))).to eq @results[:multitype]
  end

  it "shows (void) for @return [void] by default" do
    YARD.parse_string <<-'eof'
      # @return [void]
      def foo; end
    eof
    expect(trim(signature(Registry.at('#foo')))).to eq @results[:void]
  end

  it "does not show return for @return [void] if :hide_void_return is true" do
    @options.hide_void_return = true
    YARD.parse_string <<-'eof'
      # @return [void]
      def foo; end
    eof
    expect(trim(signature(Registry.at('#foo')))).to eq @results[:hide_void]
  end

  it "shows block for method with yield" do
    YARD.parse_string <<-'eof'
      def foo; yield(a, b, c) end
    eof
    expect(trim(signature(Registry.at('#foo')))).to eq @results[:block]
  end

  it "uses regular return tag if the @overload is empty" do
    YARD.parse_string <<-'eof'
      # @overload foobar
      #   Hello world
      # @return [String]
      def foo; end
    eof
    expect(trim(signature(Registry.at('#foo').tag(:overload)))).to eq @results[:empty_overload]
  end
end
