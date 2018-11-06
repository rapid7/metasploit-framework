# frozen_string_literal: true
require File.dirname(__FILE__) + '/spec_helper'

RSpec.describe "YARD::Handlers::Ruby::#{LEGACY_PARSER ? "Legacy::" : ""}ExceptionHandler" do
  before(:all) { parse_file :exception_handler_001, __FILE__ }

  it "does not document an exception outside of a method" do
    expect(P('Testing').has_tag?(:raise)).to be false
  end

  it "documents a valid raise" do
    expect(P('Testing#mymethod').tag(:raise).types).to eq ['ArgumentError']
  end

  it "only documents non-dynamic raises" do
    expect(P('Testing#mymethod2').tag(:raise)).to be nil
    expect(P('Testing#mymethod6').tag(:raise)).to be nil
    expect(P('Testing#mymethod7').tag(:raise)).to be nil
  end

  it "treats ConstantName.new as a valid exception class" do
    expect(P('Testing#mymethod8').tag(:raise).types).to eq ['ExceptionClass']
  end

  it "does not document a method with an existing @raise tag" do
    expect(P('Testing#mymethod3').tag(:raise).types).to eq ['A']
  end

  it "only documents the first raise message of a method (limitation of exception handler)" do
    expect(P('Testing#mymethod4').tag(:raise).types).to eq ['A']
  end

  it "handles complex class names" do
    expect(P('Testing#mymethod5').tag(:raise).types).to eq ['YARD::Parser::UndocumentableError']
  end

  it "ignores any raise calls on a receiver" do
    expect(P('Testing#mymethod9').tag(:raise)).to be nil
  end

  it "handles raise expressions that are method calls" do
    expect(P('Testing#mymethod10').tag(:raise)).to be nil
    expect(P('Testing#mymethod11').tag(:raise)).to be nil
  end

  it "ignores empty raise call" do
    expect(P('Testing#mymethod12').tag(:raise)).to be nil
  end
end
