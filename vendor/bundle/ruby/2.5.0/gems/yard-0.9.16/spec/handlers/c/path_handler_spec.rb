# frozen_string_literal: true
require File.dirname(__FILE__) + "/spec_helper"

RSpec.describe YARD::Handlers::C::PathHandler do
  it "tracks variable names defined under namespaces" do
    parse_init <<-eof
      mFoo = rb_define_module("Foo");
      cBar = rb_define_class_under(mFoo, "Bar", rb_cObject);
      rb_define_method(cBar, "foo", foo, 1);
    eof
    expect(Registry.at('Foo::Bar')).not_to be nil
    expect(Registry.at('Foo::Bar#foo')).not_to be nil
  end

  it "tracks variable names defined under namespaces" do
    parse_init <<-eof
      mFoo = rb_define_module("Foo");
      cBar = rb_define_class_under(mFoo, "Bar", rb_cObject);
      mBaz = rb_define_module_under(cBar, "Baz");
      rb_define_method(mBaz, "foo", foo, 1);
    eof
    expect(Registry.at('Foo::Bar::Baz')).not_to be nil
    expect(Registry.at('Foo::Bar::Baz#foo')).not_to be nil
  end

  it "handles rb_path2class() calls" do
    parse_init <<-eof
      somePath = rb_path2class("Foo::Bar::Baz")
      mFoo = rb_define_module("Foo");
      cBar = rb_define_class_under(mFoo, "Bar", rb_cObject);
      mBaz = rb_define_module_under(cBar, "Baz");
      rb_define_method(somePath, "foo", foo, 1);
    eof
    expect(Registry.at('Foo::Bar::Baz#foo')).not_to be nil
  end
end
