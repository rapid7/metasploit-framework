# frozen_string_literal: true
require File.dirname(__FILE__) + '/spec_helper'

RSpec.describe "YARD::Handlers::Ruby::#{LEGACY_PARSER ? "Legacy::" : ""}ClassVariableHandler" do
  before(:all) { parse_file :class_variable_handler_001, __FILE__ }

  it "does not parse class variables inside methods" do
    obj = Registry.at("A::B::@@somevar")
    expect(obj.source).to eq "@@somevar = \"hello\""
    expect(obj.value).to eq '"hello"'
  end
end
