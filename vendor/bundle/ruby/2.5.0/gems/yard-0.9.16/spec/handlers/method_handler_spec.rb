# frozen_string_literal: true
require File.dirname(__FILE__) + '/spec_helper'

RSpec.describe "YARD::Handlers::Ruby::#{LEGACY_PARSER ? "Legacy::" : ""}MethodHandler" do
  before(:all) do
    log.enter_level(Logger::ERROR) do
      parse_file :method_handler_001, __FILE__
    end
  end

  it "adds methods to parent's #meths list" do
    expect(P(:Foo).meths).to include(P("Foo#method1"))
  end

  it "parses and adds class methods (self.method2)" do
    expect(P(:Foo).meths).to include(P("Foo.method2"))
  end

  it "parses and adds class methods from other namespaces (String.hello)" do
    expect(P("String.hello")).to be_instance_of(CodeObjects::MethodObject)
  end

  [:[], :[]=, :allowed?, :/, :=~, :==, :`, :|, :*, :&, :%, :'^', :-@, :+@, :'~@'].each do |name|
    it "allows valid method #{name}" do
      expect(Registry.at("Foo##{name}")).not_to be nil
    end
  end

  it "allows self.methname" do
    expect(Registry.at("Foo.new")).not_to be nil
  end

  it "marks dynamic methods as such" do
    expect(P('Foo#dynamic').dynamic?).to be true
  end

  it "shows that a method is explicitly defined (if it was originally defined implicitly by attribute)" do
    expect(P('Foo#method1').is_explicit?).to be true
  end

  it "handles parameters" do
    expect(P('Foo#[]').parameters).to eq [['key', "'default'"]]
    expect(P('Foo#/').parameters).to eq [['x', "File.new('x', 'w')"], ['y', '2']]
  end

  it "handles opts = {} as parameter" do
    expect(P('Foo#optsmeth').parameters).to eq [['x', nil], ['opts', '{}']]
  end

  it "handles &block as parameter" do
    expect(P('Foo#blockmeth').parameters).to eq [['x', nil], ['&block', nil]]
  end

  it "handles double splats" do
    expect(P('Foo#d_splat').parameters).to eq [["reg", nil], ["**opts", nil]]
    expect(P('Foo#d_unnamed_splat').parameters).to eq []
  end

  it "handles overloads" do
    meth = P('Foo#foo')

    o1 = meth.tags(:overload).first
    expect(o1.name).to eq :bar
    expect(o1.parameters).to eq [['a', nil], ['b', "1"]]
    expect(o1.tag(:return).type).to eq "String"

    o2 = meth.tags(:overload)[1]
    expect(o2.name).to eq :baz
    expect(o2.parameters).to eq [['b', nil], ['c', nil]]
    expect(o2.tag(:return).type).to eq "Fixnum"

    o3 = meth.tags(:overload)[2]
    expect(o3.name).to eq :bang
    expect(o3.parameters).to eq [['d', nil], ['e', nil]]
    expect(o3.docstring).to be_empty
    expect(o3.docstring).to be_blank
  end

  it "sets a return tag if not set on #initialize" do
    meth = P('Foo#initialize')

    expect(meth).to have_tag(:return)
    expect(meth.tag(:return).types).to eq ["Foo"]
    expect(meth.tag(:return).text).to eq "a new instance of Foo"
  end

  %w(inherited included method_added method_removed method_undefined).each do |meth|
    it "sets @private tag on #{meth} callback method if no docstring is set" do
      expect(P('Foo.' + meth)).to have_tag(:private)
    end
  end

  it "does not set @private tag on extended callback method since docstring is set" do
    expect(P('Foo.extended')).not_to have_tag(:private)
  end

  it "adds @return [Boolean] tag to methods ending in ? without return types" do
    meth = P('Foo#boolean?')
    expect(meth).to have_tag(:return)
    expect(meth.tag(:return).types).to eq ['Boolean']
  end

  it "adds Boolean type to return tag without types" do
    meth = P('Foo#boolean2?')
    expect(meth).to have_tag(:return)
    expect(meth.tag(:return).types).to eq ['Boolean']
  end

  it "does not change return type for method ending in ? with return types set" do
    meth = P('Foo#boolean3?')
    expect(meth).to have_tag(:return)
    expect(meth.tag(:return).types).to eq ['NotBoolean', 'nil']
  end

  it "does not change return type for method ending in ? with return types set by @overload" do
    meth = P('Foo#rainy?')
    expect(meth).to have_tag(:overload)
    expect(meth.tag(:overload)).to have_tag(:return)
    expect(meth).not_to have_tag(:return)
  end

  it "adds method writer to existing attribute" do
    expect(Registry.at('Foo#attr_name')).to be_reader
    expect(Registry.at('Foo#attr_name=')).to be_writer
  end

  it "adds method reader to existing attribute" do
    expect(Registry.at('Foo#attr_name2')).to be_reader
    expect(Registry.at('Foo#attr_name2=')).to be_writer
  end

  it "generates an options parameter if @option refers to an undocumented parameter" do
    meth = P('Foo#auto_opts')
    expect(meth).to have_tag(:param)
    expect(meth.tag(:param).name).to eq "opts"
    expect(meth.tag(:param).types).to eq ["Hash"]
  end

  it "raises an undocumentable error when a method is defined on an object instance" do
    undoc_error "error = Foo; def error.at(foo) end"
    expect(Registry.at('error')).to be nil
  end

  it "allows class method to be defined on constant reference object" do
    expect(Registry.at('Foo.meth_on_const')).not_to be nil
    expect(Registry.at('Foo.meth2_on_const')).not_to be nil
  end

  it "copies alias information on method (re-)definition to new method" do
    expect(Registry.at('D').aliases).to be_empty
    expect(Registry.at('D#b').is_alias?).to be false
    expect(Registry.at('D#a').is_alias?).to be false
  end

  it "adds macros for class methods" do
    macro = CodeObjects::MacroObject.find('prop')
    expect(macro).not_to be nil
    expect(macro.macro_data).to eq "@!method $1(value)\n$3\n@return [$2]"
    expect(macro.method_object).to eq Registry.at('E.property')
    expect(macro).to be_attached
    obj = Registry.at('E#foo')
    expect(obj).not_to be nil
    expect(obj.docstring).to eq 'create a foo'
    expect(obj.signature).to eq 'def foo(value)'
    expect(obj.tag(:return).types).to eq ['String']
  end

  it "handles macros on any object" do
    macro = CodeObjects::MacroObject.find('xyz')
    expect(macro).not_to be nil
    expect(macro.macro_data).to eq '@!method $1'
  end

  it "skips macros on instance methods" do
    expect(Registry.at('E#a')).to be nil
  end

  it "warns if the macro name is invalid" do
    expect(log).to receive(:warn).with(/Invalid directive.*@!macro/)
    YARD.parse_string "class Foo\n# @!macro\ndef self.foo; end\nend"
  end

  it "handles 'def end' methods" do
    obj = Registry.at('F::A#foo')
    expect(obj).not_to be nil
    obj = Registry.at('F::A#bar')
    expect(obj).not_to be nil
    expect(obj.docstring).to eq 'PASS'
  end
end
