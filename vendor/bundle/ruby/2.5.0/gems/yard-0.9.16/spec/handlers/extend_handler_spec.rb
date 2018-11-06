# frozen_string_literal: true
require File.dirname(__FILE__) + '/spec_helper'

RSpec.describe "YARD::Handlers::Ruby::#{LEGACY_PARSER ? "Legacy::" : ""}ExtendHandler" do
  before(:all) { parse_file :extend_handler_001, __FILE__ }

  it "includes modules at class scope" do
    expect(Registry.at(:B).class_mixins).to eq [P(:A)]
    expect(Registry.at(:B).instance_mixins).to be_empty
  end

  it "handles a module extending itself" do
    expect(Registry.at(:C).class_mixins).to eq [P(:C)]
    expect(Registry.at(:C).instance_mixins).to be_empty
  end

  it "extends module with correct namespace" do
    expect(Registry.at('Q::R::S').class_mixins.first.path).to eq 'A'
  end

  it "does not allow extending self if object is a class" do
    undoc_error "class Foo; extend self; end"
  end
end
