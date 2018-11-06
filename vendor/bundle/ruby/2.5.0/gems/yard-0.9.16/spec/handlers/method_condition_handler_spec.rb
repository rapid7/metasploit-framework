# frozen_string_literal: true
require File.dirname(__FILE__) + '/spec_helper'

RSpec.describe "YARD::Handlers::Ruby::#{LEGACY_PARSER ? "Legacy::" : ""}MethodConditionHandler" do
  before(:all) { parse_file :method_condition_handler_001, __FILE__ }

  it "does not parse regular if blocks in methods" do
    expect(Registry.at('#b')).to be nil
  end

  it "parses if/unless blocks in the form X if COND" do
    expect(Registry.at('#c')).not_to be nil
    expect(Registry.at('#d')).not_to be nil
  end
end
