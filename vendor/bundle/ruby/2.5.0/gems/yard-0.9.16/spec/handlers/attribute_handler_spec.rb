# frozen_string_literal: true
require File.dirname(__FILE__) + '/spec_helper'

RSpec.describe "YARD::Handlers::Ruby::#{LEGACY_PARSER ? "Legacy::" : ""}AttributeHandler" do
  before(:all) { parse_file :attribute_handler_001, __FILE__ }

  def read_write(namespace, name, read, write, scope = :instance)
    rname = namespace.to_s + "#" + name.to_s
    wname = namespace.to_s + "#" + name.to_s + "="
    if read
      expect(Registry.at(rname)).to be_instance_of(CodeObjects::MethodObject)
    else
      expect(Registry.at(rname)).to eq nil
    end

    if write
      expect(Registry.at(wname)).to be_kind_of(CodeObjects::MethodObject)
    else
      expect(Registry.at(wname)).to eq nil
    end

    attrs = Registry.at(namespace).attributes[scope][name]
    expect(attrs[:read]).to eq(read ? Registry.at(rname) : nil)
    expect(attrs[:write]).to eq(write ? Registry.at(wname) : nil)
  end

  it "parses attributes inside modules too" do
    expect(Registry.at("A#x=")).not_to eq nil
  end

  it "parses 'attr'" do
    read_write(:B, :a, true, true)
    read_write(:B, :a2, true, false)
    read_write(:B, "a3", true, false)
  end

  it "parses 'attr_reader'" do
    read_write(:B, :b, true, false)
  end

  it "parses 'attr_writer'" do
    read_write(:B, :e, false, true)
  end

  it "parses 'attr_accessor'" do
    read_write(:B, :f, true, true)
  end

  it "parses a list of attributes" do
    read_write(:B, :b, true, false)
    read_write(:B, :c, true, false)
    read_write(:B, :d, true, false)
  end

  it "has a default docstring if one is not supplied" do
    expect(Registry.at("B#f=").docstring).not_to be_empty
  end

  it "sets the correct docstring if one is supplied" do
    expect(Registry.at("B#b").docstring).to eq "Docstring"
    expect(Registry.at("B#c").docstring).to eq "Docstring"
    expect(Registry.at("B#d").docstring).to eq "Docstring"
  end

  it "is able to differentiate between class and instance attributes" do
    expect(P('B').class_attributes[:z][:read].scope).to eq :class
    expect(P('B').instance_attributes[:z][:read].scope).to eq :instance
  end

  it "responds true in method's #is_attribute?" do
    expect(P('B#a').is_attribute?).to be true
    expect(P('B#a=').is_attribute?).to be true
  end

  it "does not return true for #is_explicit? in created methods" do
    Registry.at(:B).meths.each do |meth|
      expect(meth.is_explicit?).to be false
    end
  end

  it "handles attr call with no arguments" do
    expect { StubbedSourceParser.parse_string "attr" }.not_to raise_error
  end

  it "adds existing reader method as part of attr_writer combo" do
    expect(Registry.at('C#foo=').attr_info[:read]).to eq Registry.at('C#foo')
  end

  it "adds existing writer method as part of attr_reader combo" do
    expect(Registry.at('C#foo').attr_info[:write]).to eq Registry.at('C#foo=')
  end

  it "maintains visibility for attr_reader" do
    expect(Registry.at('D#parser').visibility).to eq :protected
  end
end
