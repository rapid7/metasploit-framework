# frozen_string_literal: true
require File.dirname(__FILE__) + '/spec_helper'

RSpec.describe YARD::Handlers::C::StructHandler do
  after { Registry.clear }

  it "handles Struct class definitions" do
    parse_init <<-eof
      rb_cRange = rb_struct_define_without_accessor(
          "Range", rb_cFoo, range_alloc,
          "begin", "end", "excl", NULL);
    eof
    expect(Registry.at('Range').type).to eq :class
    expect(Registry.at('Range').superclass).to eq P(:Foo)
  end
end
