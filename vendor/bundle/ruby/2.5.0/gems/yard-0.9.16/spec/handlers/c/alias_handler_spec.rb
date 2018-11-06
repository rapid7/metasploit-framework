# frozen_string_literal: true
require File.dirname(__FILE__) + "/spec_helper"

RSpec.describe YARD::Handlers::C::AliasHandler do
  it "allows defining of aliases (rb_define_alias)" do
    parse <<-eof
      /* FOO */
      VALUE foo(VALUE x) { int value = x; }
      void Init_Foo() {
        rb_cFoo = rb_define_class("Foo", rb_cObject);
        rb_define_method(rb_cFoo, "foo", foo, 1);
        rb_define_alias(rb_cFoo, "bar", "foo");
      }
    eof

    expect(Registry.at('Foo#bar')).to be_is_alias
    expect(Registry.at('Foo#bar').docstring).to eq 'FOO'
  end

  it "allows defining of aliases (rb_define_alias) of attributes" do
    parse <<-eof
      /* FOO */
      VALUE foo(VALUE x) { int value = x; }
      void Init_Foo() {
        rb_cFoo = rb_define_class("Foo", rb_cObject);
        rb_define_attr(rb_cFoo, "foo", 1, 0);
        rb_define_alias(rb_cFoo, "foo?", "foo");
      }
    eof

    expect(Registry.at('Foo#foo')).to be_reader
    expect(Registry.at('Foo#foo?')).to be_is_alias
  end
end
