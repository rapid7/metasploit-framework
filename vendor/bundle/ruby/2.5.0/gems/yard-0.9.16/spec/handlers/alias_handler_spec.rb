# frozen_string_literal: true
require File.dirname(__FILE__) + '/spec_helper'

RSpec.describe "YARD::Handlers::Ruby::#{LEGACY_PARSER ? "Legacy::" : ""}AliasHandler" do
  before(:all) { parse_file :alias_handler_001, __FILE__ }

  it "throws alias into namespace object list" do
    expect(P(:A).aliases[P("A#b")]).to eq :a
  end

  ['c', 'd?', '[]', '[]=', '-@', '%', '*', 'cstrkey', 'cstrmeth'].each do |a|
    it "handles the Ruby 'alias' keyword syntax for method ##{a}" do
      expect(P('A#' + a)).to be_instance_of(CodeObjects::MethodObject)
      expect(P('A#' + a).is_alias?).to be true
    end
  end

  it "handles keywords as the alias name" do
    expect(P('A#for')).to be_instance_of(CodeObjects::MethodObject)
  end

  it "allows ConstantNames to be specified as aliases" do
    expect(P('A#ConstantName')).to be_instance_of(CodeObjects::MethodObject)
  end

  it "creates a new method object for the alias" do
    expect(P("A#b")).to be_instance_of(CodeObjects::MethodObject)
  end

  it "pulls the method into the current class if it's from another one" do
    expect(P(:B).aliases[P("B#q")]).to eq :x
    expect(P(:B).aliases[P("B#r?")]).to eq :x
  end

  it "gracefully fails to pull a method in if the original method cannot be found" do
    expect(P(:B).aliases[P("B#s")]).to eq :to_s
  end

  it "allows complex Ruby expressions after the alias parameters" do
    expect(P(:B).aliases[P("B#t")]).to eq :inspect
  end

  it "shows up in #is_alias? for method" do
    expect(P("B#t").is_alias?).to be true
    expect(P('B#r?').is_alias?).to be true
  end

  it "allows operators and keywords to be specified as symbols" do
    expect(P('B#<<')).to be_instance_of(CodeObjects::MethodObject)
    expect(P('B#for')).to be_instance_of(CodeObjects::MethodObject)
  end

  it "handles keywords in alias names" do
    expect(P('B#do').is_alias?).to be true
    expect(P('B#x2').is_alias?).to be true
    expect(P(:B).aliases[P('B#do')]).to eq :x
    expect(P(:B).aliases[P('B#x2')]).to eq :do
  end

  it "handles quoted symbols" do
    foo = Registry.at('A#foo')
    expect(foo).not_to be nil
    expect(foo.is_alias?).to be true
    expect(Registry.at('A').aliases[foo]).to eq :a
  end

  it "prepends aliases object's docstring to comments" do
    expect(Registry.at('D#a').tag(:return).types).to eq ['Numeric']
    expect(Registry.at('D#b').tag(:return).types).to eq ['String']
    expect(Registry.at('D#b').docstring).to eq "Foo bar"
  end

  it "raises an UndocumentableError if only one parameter is passed" do
    undoc_error "alias_method :q"
  end

  it "raises an UndocumentableError if the parameter is not a Symbol or String" do
    undoc_error "alias_method CONST, Something"
    undoc_error "alias_method variable, ClassName"
    undoc_error "alias_method variable, other_variable"
  end
end
