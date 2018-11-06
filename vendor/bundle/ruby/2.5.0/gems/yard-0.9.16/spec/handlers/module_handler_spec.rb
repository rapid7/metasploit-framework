# frozen_string_literal: true
require File.dirname(__FILE__) + '/spec_helper'

RSpec.describe "YARD::Handlers::Ruby::#{LEGACY_PARSER ? "Legacy::" : ""}ModuleHandler" do
  before(:all) { parse_file :module_handler_001, __FILE__ }

  it "parses a module block" do
    expect(Registry.at(:ModName)).not_to eq nil
    expect(Registry.at("ModName::OtherModName")).not_to eq nil
  end

  it "attaches docstring" do
    expect(Registry.at("ModName::OtherModName").docstring).to eq "Docstring"
  end

  it "handles any formatting" do
    expect(Registry.at(:StressTest)).not_to eq nil
  end

  it "handles complex module names" do
    expect(Registry.at("A::B")).not_to eq nil
  end

  it "handles modules in the form ::ModName" do
    expect(Registry.at("Kernel")).not_to be nil
  end

  it "lists mixins in proper order" do
    expect(Registry.at('D').mixins).to eq [P(:C), P(:B), P(:A)]
  end

  it "creates proper module when constant is in namespace" do
    expect(Registry.at('Q::FOO::A')).not_to be nil
  end
end
