# frozen_string_literal: true
require File.dirname(__FILE__) + '/spec_helper'

RSpec.describe "YARD::Handlers::Ruby::#{LEGACY_PARSER ? "Legacy::" : ""}PrivateConstantHandler" do
  before(:all) { parse_file :private_constant_handler_001, __FILE__ }

  it "handles private_constant statement" do
    expect(Registry.at('A::Foo').visibility).to eq :private
    expect(Registry.at('A::B').visibility).to eq :private
    expect(Registry.at('A::C').visibility).to eq :private
  end

  it "makes all other constants public" do
    expect(Registry.at('A::D').visibility).to eq :public
  end

  it "fails if parameter is not String, Symbol or Constant" do
    undoc_error 'class Foo; private_constant x; end'
    undoc_error 'class Foo; X = 1; private_constant X.new("hi"); end'
  end unless LEGACY_PARSER

  it "fails if constant can't be recognized" do
    undoc_error 'class Foo2; private_constant :X end'
  end
end
