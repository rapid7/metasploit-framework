# frozen_string_literal: true
require File.dirname(__FILE__) + '/spec_helper'

RSpec.describe YARD::CodeObjects::MacroObject do
  before do
    Registry.clear
  end

  describe ".create" do
    def create(*args) MacroObject.create(*args) end

    it "creates an object" do
      create('foo', '')
      obj = Registry.at('.macro.foo')
      expect(obj).not_to be nil
    end

    it "uses identity map" do
      obj1 = create('foo', '')
      obj2 = create('foo', '')
      expect(obj1.object_id).to eq obj2.object_id
    end

    it "allows specifying of macro data" do
      obj = create('foo', 'MACRODATA')
      expect(obj.macro_data).to eq 'MACRODATA'
    end

    context "if a method object is provided" do
      it "attaches it" do
        obj = create('foo', 'MACRODATA', P('Foo.property'))
        expect(obj.method_object).to eq P('Foo.property')
        expect(obj).to be_attached
      end
    end
  end

  describe ".find" do
    before { MacroObject.create('foo', 'DATA') }

    it "searches for an object by name" do
      expect(MacroObject.find('foo').macro_data).to eq 'DATA'
    end

    it "accepts Symbol" do
      expect(MacroObject.find(:foo).macro_data).to eq 'DATA'
    end
  end

  describe ".find_or_create" do
    it "looks up name if @!macro is present and find object" do
      macro1 = MacroObject.create('foo', 'FOO')
      macro2 = MacroObject.find_or_create('foo', "a b c")
      expect(macro1).to eq macro2
    end

    it "creates new macro if macro by that name does not exist" do
      MacroObject.find_or_create('foo', "@!method $1")
      expect(MacroObject.find('foo').macro_data).to eq "@!method $1"
    end
  end

  describe ".apply" do
    let(:args) { %w(foo a b c) }

    def apply(comments)
      MacroObject.apply(comments, args)
    end

    it "only expands macros if @macro is present" do
      expect(apply("$1$2$3")).to eq "$1$2$3"
    end

    it "handles macro text inside block" do
      expect(apply("@!macro\n  foo$1$2$3\nfoobaz")).to eq "fooabc\nfoobaz"
    end

    it "appends docstring to existing macro" do
      MacroObject.create('name', '$3$2$1')
      result = MacroObject.apply("@!macro name\nfoobar", args)
      expect(result).to eq "cba\nfoobar"
    end

    it "uses only non-macro data if docstring is an existing macro" do
      data = "@!macro name\n  $3$2$1\nEXTRA"
      result = MacroObject.apply(data, args, 'SOURCE')
      expect(result).to eq "cba\nEXTRA"
      expect(MacroObject.apply("@!macro name\nFOO", args)).to eq "cba\nFOO"
    end

    it "creates macros if they don't exist" do
      result = MacroObject.apply("@!macro name\n  foo!$1", args, 'SOURCE')
      expect(result).to eq "foo!a"
      expect(MacroObject.find('name').macro_data).to eq 'foo!$1'
    end

    it "keeps other tags" do
      expect(apply("@!macro\n  foo$1$2$3\n@param name foo\nfoo")).to eq(
        "fooabc\nfoo\n@param name\n  foo"
      )
    end
  end

  describe ".expand" do
    def expand(comments)
      args = %w(foo a b c)
      full_line = 'foo :bar, :baz'
      MacroObject.expand(comments, args, full_line)
    end

    it "allows escaping of macro syntax" do
      expect(expand("$1\\$2$3")).to eq "a$2c"
    end

    it "replaces $* with the whole statement" do
      expect(expand("$* ${*}")).to eq "foo :bar, :baz foo :bar, :baz"
    end

    it "replaces $0 with method name" do
      expect(expand("$0 ${0}")).to eq "foo foo"
    end

    it "replaces all $N values with the Nth argument in the method call" do
      expect(expand("$1$2$3${3}\nfoobar")).to eq "abcc\nfoobar"
    end

    it "replaces ${N-M} ranges with N-M arguments (incl. commas)" do
      expect(expand("${1-2}x")).to eq "a, bx"
    end

    it "handles open ended ranges (${N-})" do
      expect(expand("${2-}")).to eq "b, c"
    end

    it "handles negative indexes ($-N)" do
      expect(expand("$-1 ${-2-} ${-2--2}")).to eq "c b, c b"
    end

    it "accepts Docstring objects" do
      expect(expand(Docstring.new("$1\n@param name foo"))).to eq "a\n@param name foo"
    end
  end

  describe "#expand" do
    it "expands a macro given its data" do
      macro = MacroObject.create_docstring('foo', '$1 $2 THREE!')
      expect(macro.expand(['NAME', 'ONE', 'TWO'])).to eq "ONE TWO THREE!"
    end
  end
end
