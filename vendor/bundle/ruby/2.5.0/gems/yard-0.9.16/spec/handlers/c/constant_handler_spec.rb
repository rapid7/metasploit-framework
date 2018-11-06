# frozen_string_literal: true
require File.dirname(__FILE__) + "/spec_helper"

RSpec.describe YARD::Handlers::C::ConstantHandler do
  it "registers constants" do
    parse_init <<-eof
      mFoo = rb_define_module("Foo");
      rb_define_const(mFoo, "FOO", ID2SYM(100));
      rb_define_global_const("BAR", ID2SYM(100));
    eof
    expect(Registry.at('Foo::FOO').type).to eq :constant
    expect(Registry.at('BAR').type).to eq :constant
  end

  it "looks for override comments" do
    parse <<-eof
      /* Document-const: FOO
       * Document-const: Foo::BAR
       * Foo bar!
       */

      void Init_Foo() {
        mFoo = rb_define_module("Foo");
        rb_define_const(mFoo, "FOO", ID2SYM(100));
        rb_define_const(mFoo, "BAR", ID2SYM(101));
      }
    eof
    foo = Registry.at('Foo::FOO')
    expect(foo.type).to eq :constant
    expect(foo.docstring).to eq 'Foo bar!'
    expect(foo.value).to eq 'ID2SYM(100)'
    expect(foo.file).to eq '(stdin)'
    expect(foo.line).to eq 8
    bar = Registry.at('Foo::BAR')
    expect(bar.type).to eq :constant
    expect(bar.docstring).to eq 'Foo bar!'
    expect(bar.file).to eq '(stdin)'
    expect(bar.line).to eq 9
    expect(bar.value).to eq 'ID2SYM(101)'
  end

  it "uses comment attached to declaration as fallback" do
    parse_init <<-eof
      mFoo = rb_define_module("Foo");
      rb_define_const(mFoo, "FOO", ID2SYM(100)); // foobar!
    eof
    foo = Registry.at('Foo::FOO')
    expect(foo.value).to eq 'ID2SYM(100)'
    expect(foo.docstring).to eq 'foobar!'
  end

  it "allows the form VALUE: DOCSTRING to document value" do
    parse_init <<-eof
      mFoo = rb_define_module("Foo");
      rb_define_const(mFoo, "FOO", ID2SYM(100)); // 100: foobar!
    eof
    foo = Registry.at('Foo::FOO')
    expect(foo.value).to eq '100'
    expect(foo.docstring).to eq 'foobar!'
  end

  it "allows escaping of backslashes in VALUE: DOCSTRING syntax" do
    parse_init <<-eof
      mFoo = rb_define_module("Foo");
      rb_define_const(mFoo, "FOO", ID2SYM(100)); // 100\\:x\\:y: foobar:x!
    eof
    foo = Registry.at('Foo::FOO')
    expect(foo.value).to eq '100:x:y'
    expect(foo.docstring).to eq 'foobar:x!'
  end
end
