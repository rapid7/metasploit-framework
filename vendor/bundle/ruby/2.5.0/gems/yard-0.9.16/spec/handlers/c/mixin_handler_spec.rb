# frozen_string_literal: true
require File.dirname(__FILE__) + "/spec_helper"

RSpec.describe YARD::Handlers::C::MixinHandler do
  it "adds includes to modules or classes" do
    parse_init <<-eof
      mFoo = rb_define_module("Foo");
      cBar = rb_define_class("Bar", rb_cObject);
      mBaz = rb_define_module("Baz");
      rb_include_module(cBar, mFoo);
      rb_include_module(mBaz, mFoo);
    eof
    foo = Registry.at('Foo')
    bar = Registry.at('Bar')
    baz = Registry.at('Baz')
    expect(bar.mixins(:instance)).to eq [foo]
    expect(baz.mixins(:instance)).to eq [foo]
  end

  it "adds include as proxy if symbol lookup fails" do
    parse_init <<-eof
      mFoo = rb_define_module("Foo");
      rb_include_module(mFoo, mXYZ);
    eof
    foo = Registry.at('Foo')
    expect(foo.mixins(:instance)).to eq [P('XYZ')]
  end

  it "fails if mixin variable cannot be detected" do
    with_parser(:c) do
      undoc_error <<-eof
        void Init_Foo() {
          VALUE noprefix;

          mFoo = rb_define_module("Foo");
          // YARD doesn't understand this
          noprefix = rb_const_get(rb_cObject, rb_intern("Observable"));

          rb_include_module(mFoo, noprefix);
        }
      eof
    end
  end
end
