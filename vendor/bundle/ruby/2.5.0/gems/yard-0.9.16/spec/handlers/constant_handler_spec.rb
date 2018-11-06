# frozen_string_literal: true
require File.dirname(__FILE__) + '/spec_helper'

RSpec.describe "YARD::Handlers::Ruby::#{LEGACY_PARSER ? "Legacy::" : ""}ConstantHandler" do
  before(:all) { parse_file :constant_handler_001, __FILE__ }

  it "does not parse constants inside methods" do
    expect(Registry.at("A::B::SOMECONSTANT").source).to eq "SOMECONSTANT= \"hello\""
  end

  it "only parses valid constants" do
    expect(Registry.at("A::B::notaconstant")).to be nil
  end

  it "maintains newlines" do
    expect(Registry.at("A::B::MYCONSTANT").value.delete("\r")).to eq "A +\nB +\nC +\nD"
  end

  it "turns Const = Struct.new(:sym) into class Const with attr :sym" do
    obj = Registry.at("MyClass")
    expect(obj).to be_kind_of(CodeObjects::ClassObject)
    attrs = obj.attributes[:instance]
    [:a, :b, :c].each do |key|
      expect(attrs).to have_key(key)
      expect(attrs[key][:read]).not_to be nil
      expect(attrs[key][:write]).not_to be nil
    end
  end

  it 'documents block for Struct.new if present' do
    obj = Registry.at("MyStructWithConstant")
    expect(obj).to be_kind_of(CodeObjects::ClassObject)
    expect(obj.constants[0].docstring).to eq 'A constant.'
    expect(obj.constants[0].name).to eq :CONSTANT
    expect(obj.constants[0].value).to eq "42"
    expect(obj.constants[1].docstring).to eq 'Special constant (empty symbol)'
    expect(obj.constants[1].name).to eq :EMPTY
    expect(obj.constants[1].value).to eq ':""'
  end

  it "turns Const = Struct.new('Name', :sym) into class Const with attr :sym" do
    obj = Registry.at("NotMyClass")
    expect(obj).to be_kind_of(CodeObjects::ClassObject)
    attrs = obj.attributes[:instance]
    [:b, :c].each do |key|
      expect(attrs).to have_key(key)
      expect(attrs[key][:read]).not_to be nil
      expect(attrs[key][:write]).not_to be nil
    end

    expect(Registry.at("NotMyClass2")).to be nil
  end

  it "turns Const = Struct.new into empty struct" do
    obj = Registry.at("MyEmptyStruct")
    expect(obj).not_to be nil
    expect(obj.attributes[:instance]).to be_empty
  end

  it "maintains docstrings on structs defined via constants" do
    obj = Registry.at("DocstringStruct")
    expect(obj).not_to be nil
    expect(obj.docstring).to eq "A crazy struct."
    expect(obj.attributes[:instance]).not_to be_empty
    a1 = Registry.at("DocstringStruct#bar")
    a2 = Registry.at("DocstringStruct#baz")
    expect(a1.docstring).to eq "An attr"
    expect(a1.tag(:return).types).to eq ["String"]
    expect(a2.docstring).to eq "Another attr"
    expect(a2.tag(:return).types).to eq ["Number"]
    a3 = Registry.at("DocstringStruct#new_syntax")
    expect(a3.docstring).to eq "Attribute defined with the new syntax"
    expect(a3.tag(:return).types).to eq ["Symbol"]
  end

  it "raises undocumentable error in 1.9 parser for Struct.new assignment to non-const" do
    undoc_error "nonconst = Struct.new"
  end unless LEGACY_PARSER

  %w(module class).each do |type|
    it "does not allow #{type} to be redefined as constant" do
      undoc_error <<-eof
        #{type} Foo; end
        Foo = "value"
      eof
    end
  end unless LEGACY_PARSER

  it "allows constant to have same name as constant in parent namespace" do
    YARD.parse_string <<-eof
      module A
        class C; end
        module B; C = 1 end
      end
    eof
    expect(log.io.string).to eq ""
    expect(Registry.at('A::B::C').type).to eq :constant
  end

  it "detects compound constant names" do
    YARD.parse_string <<-eof
      module A
        class AA; end
        AA::B = true
      end
      A::AA::C = true
    eof

    expect(Registry.at('A::AA::B').type).to eq :constant
    expect(Registry.at('A::AA::C').type).to eq :constant
  end if HAVE_RIPPER
end
