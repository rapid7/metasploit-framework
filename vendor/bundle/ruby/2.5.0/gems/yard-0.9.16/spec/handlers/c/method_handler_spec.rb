# frozen_string_literal: true
require File.dirname(__FILE__) + "/spec_helper"

RSpec.describe YARD::Handlers::C::MethodHandler do
  it "registers methods" do
    parse_init <<-eof
      mFoo = rb_define_module("Foo");
      rb_define_method(mFoo, "bar", bar, 0);
    eof
    expect(Registry.at('Foo#bar')).not_to be nil
    expect(Registry.at('Foo#bar').visibility).to eq :public
  end

  it "registers private methods" do
    parse_init <<-eof
      mFoo = rb_define_module("Foo");
      rb_define_private_method(mFoo, "bar", bar, 0);
    eof
    expect(Registry.at('Foo#bar')).not_to be nil
    expect(Registry.at('Foo#bar').visibility).to eq :private
  end

  it "registers singleton methods" do
    parse_init <<-eof
      mFoo = rb_define_module("Foo");
      rb_define_singleton_method(mFoo, "bar", bar, 0);
    eof
    expect(Registry.at('Foo.bar')).not_to be nil
    expect(Registry.at('Foo.bar').visibility).to eq :public
  end

  it "registers module functions" do
    parse <<-eof
      /* DOCSTRING
       * @return [String] foo!
      */
      static VALUE bar(VALUE self) { x(); y(); z(); }

      void Init_Foo() {
        mFoo = rb_define_module("Foo");
        rb_define_module_function(mFoo, "bar", bar, 0);
      }
    eof
    bar_c = Registry.at('Foo.bar')
    bar_i = Registry.at('Foo#bar')
    expect(bar_c).to be_module_function
    expect(bar_c.visibility).to eq :public
    expect(bar_c.docstring).to eq "DOCSTRING"
    expect(bar_c.tag(:return).object).to eq bar_c
    expect(bar_c.source).to eq "static VALUE bar(VALUE self) { x(); y(); z(); }"
    expect(bar_i).not_to be_module_function
    expect(bar_i.visibility).to eq :private
    expect(bar_i.docstring).to eq "DOCSTRING"
    expect(bar_i.tag(:return).object).to eq bar_i
    expect(bar_i.source).to eq bar_c.source
  end

  it "registers global functions into Kernel" do
    parse_init 'rb_define_global_function("bar", bar, 0);'
    expect(Registry.at('Kernel#bar')).not_to be nil
  end

  it "looks for symbol containing method source" do
    parse <<-eof
      static VALUE foo(VALUE self) { x(); y(); z(); }
      VALUE bar() { a(); b(); c(); }
      void Init_Foo() {
        mFoo = rb_define_module("Foo");
        rb_define_method(mFoo, "foo", foo, 0);
        rb_define_method(mFoo, "bar", bar, 0);
      }
    eof
    foo = Registry.at('Foo#foo')
    bar = Registry.at('Foo#bar')
    expect(foo.source).to eq "static VALUE foo(VALUE self) { x(); y(); z(); }"
    expect(foo.file).to eq '(stdin)'
    expect(foo.line).to eq 1
    expect(bar.source).to eq "VALUE bar() { a(); b(); c(); }"
    expect(bar.file).to eq '(stdin)'
    expect(bar.line).to eq 2
  end

  it "finds docstrings attached to method symbols" do
    parse <<-eof
      /* DOCSTRING */
      static VALUE foo(VALUE self) { x(); y(); z(); }
      void Init_Foo() {
        mFoo = rb_define_module("Foo");
        rb_define_method(mFoo, "foo", foo, 0);
      }
    eof
    foo = Registry.at('Foo#foo')
    expect(foo.docstring).to eq 'DOCSTRING'
  end

  it "uses declaration comments as docstring if there are no others" do
    parse <<-eof
      static VALUE foo(VALUE self) { x(); y(); z(); }
      void Init_Foo() {
        mFoo = rb_define_module("Foo");
        /* DOCSTRING */
        rb_define_method(mFoo, "foo", foo, 0);
        // DOCSTRING!
        rb_define_method(mFoo, "bar", bar, 0);
      }
    eof
    foo = Registry.at('Foo#foo')
    expect(foo.docstring).to eq 'DOCSTRING'
    bar = Registry.at('Foo#bar')
    expect(bar.docstring).to eq 'DOCSTRING!'
  end

  it "looks for symbols in other file" do
    other = <<-eof
      /* DOCSTRING! */
      static VALUE foo() { x(); }
    eof
    expect(File).to receive(:read).with('other.c').and_return(other)
    parse <<-eof
      void Init_Foo() {
        mFoo = rb_define_module("Foo");
        rb_define_method(mFoo, "foo", foo, 0); // in other.c
      }
    eof
    foo = Registry.at('Foo#foo')
    expect(foo.docstring).to eq 'DOCSTRING!'
    expect(foo.file).to eq 'other.c'
    expect(foo.line).to eq 2
    expect(foo.source).to eq 'static VALUE foo() { x(); }'
  end

  it "allows extra file to include /'s and other filename characters" do
    expect(File).to receive(:read).at_least(1).times.with('ext/a-file.c').and_return(<<-eof)
      /* FOO */
      VALUE foo(VALUE x) { int value = x; }

      /* BAR */
      VALUE bar(VALUE x) { int value = x; }
    eof
    parse_init <<-eof
      rb_define_method(rb_cFoo, "foo", foo, 1); /* in ext/a-file.c */
      rb_define_global_function("bar", bar, 1); /* in ext/a-file.c */
    eof
    expect(Registry.at('Foo#foo').docstring).to eq 'FOO'
    expect(Registry.at('Kernel#bar').docstring).to eq 'BAR'
  end

  it "warns if other file can't be found" do
    expect(log).to receive(:warn).with(/Missing source file `other.c' when parsing Foo#foo/)
    parse <<-eof
      void Init_Foo() {
        mFoo = rb_define_module("Foo");
        rb_define_method(mFoo, "foo", foo, 0); // in other.c
      }
    eof
  end

  it "looks at override comments for docstring" do
    parse <<-eof
      /* Document-method: Foo::foo
       * Document-method: new
       * Document-method: Foo::Bar#baz
       * Foo bar!
       */

      // init comments
      void Init_Foo() {
        mFoo = rb_define_module("Foo");
        rb_define_method(mFoo, "foo", foo, 0);
        rb_define_method(mFoo, "initialize", foo, 0);
        mBar = rb_define_module_under(mFoo, "Bar");
        rb_define_method(mBar, "baz", foo, 0);
      }
    eof
    expect(Registry.at('Foo#foo').docstring).to eq 'Foo bar!'
    expect(Registry.at('Foo#initialize').docstring).to eq 'Foo bar!'
    expect(Registry.at('Foo::Bar#baz').docstring).to eq 'Foo bar!'
  end

  it "looks at overrides in other files" do
    other = <<-eof
      /* Document-method: Foo::foo
       * Document-method: new
       * Document-method: Foo::Bar#baz
       * Foo bar!
       */
    eof
    expect(File).to receive(:read).with('foo/bar/other.c').and_return(other)
    src = <<-eof
      void Init_Foo() {
        mFoo = rb_define_module("Foo");
        rb_define_method(mFoo, "foo", foo, 0); // in foo/bar/other.c
        rb_define_method(mFoo, "initialize", foo, 0); // in foo/bar/other.c
        mBar = rb_define_module_under(mFoo, "Bar"); // in foo/bar/other.c
        rb_define_method(mBar, "baz", foo, 0); // in foo/bar/other.c
      }
    eof
    parse(src, 'foo/bar/baz/init.c')
    expect(Registry.at('Foo#foo').docstring).to eq 'Foo bar!'
    expect(Registry.at('Foo#initialize').docstring).to eq 'Foo bar!'
    expect(Registry.at('Foo::Bar#baz').docstring).to eq 'Foo bar!'
  end

  it "adds return tag on methods ending in '?'" do
    parse <<-eof
      /* DOCSTRING */
      static VALUE foo(VALUE self) { x(); y(); z(); }
      void Init_Foo() {
        mFoo = rb_define_module("Foo");
        rb_define_method(mFoo, "foo?", foo, 0);
      }
    eof
    foo = Registry.at('Foo#foo?')
    expect(foo.docstring).to eq 'DOCSTRING'
    expect(foo.tag(:return).types).to eq ['Boolean']
  end

  it "does not add return tag if return tags exist" do
    parse <<-eof
      // @return [String] foo
      static VALUE foo(VALUE self) { x(); y(); z(); }
      void Init_Foo() {
        mFoo = rb_define_module("Foo");
        rb_define_method(mFoo, "foo?", foo, 0);
      }
    eof
    foo = Registry.at('Foo#foo?')
    expect(foo.tag(:return).types).to eq ['String']
  end

  it "handles casted method names" do
    parse_init <<-eof
      mFoo = rb_define_module("Foo");
      rb_define_method(mFoo, "bar", (METHOD)bar, 0);
      rb_define_global_function("baz", (METHOD)baz, 0);
    eof
    expect(Registry.at('Foo#bar')).not_to be nil
    expect(Registry.at('Kernel#baz')).not_to be nil
  end

  it "extracts at regular method parameters from C function signatures" do
    parse <<-eof
      static VALUE noargs_func(VALUE self) { return Qnil; }
      static VALUE twoargs_func(VALUE self, VALUE a, VALUE b) { return a; }
      void Init_Foo() {
        mFoo = rb_define_module("Foo");
        rb_define_method(mFoo, "noargs", noargs_func, 0);
        rb_define_method(mFoo, "twoargs", twoargs_func, 2);
      }
    eof
    expect(Registry.at('Foo#noargs').parameters).to be_empty
    expect(Registry.at('Foo#twoargs').parameters).to eq [['a', nil], ['b', nil]]
  end

  it "extracts at varargs method parameters from C function signatures" do
    parse <<-eof
      static VALUE varargs_func(int argc, VALUE *argv, VALUE self) { return self; }
      /* let's see if parser is robust in the face of strange spacing */
      static VALUE varargs_func2(	int 	argc ,	VALUE
	* 	 argv  ,VALUE  self	)

      {return self;}
      void Init_Foo() {
        mFoo = rb_define_module("Foo");
        rb_define_method(mFoo, "varargs", varargs_func, -1);
        rb_define_method(	mFoo	,"varargs2",varargs_func2		,-1);
      }
    eof
    expect(Registry.at('Foo#varargs').parameters).to eq [['*args', nil]]
    expect(Registry.at('Foo#varargs2').parameters).to eq [['*args', nil]]
  end

  it "is not too strict or too loose about matching override comments to methods" do
    parse <<-eof
      /* Document-method: Foo::foo
       * Document-method: new
       * Document-method: Foo::Bar#baz
       * Foo bar!
       */

      void Init_Foo() {
        mFoo = rb_define_module("Foo");
        mBar = rb_define_module_under(mFoo, "Bar");

        rb_define_method(mFoo, "foo", foo, 0);
        rb_define_singleton_method(mFoo, "foo", foo, 0);
        rb_define_method(mBar, "foo", foo, 0);
        rb_define_singleton_method(mBar, "foo", foo, 0);

        rb_define_method(mFoo, "initialize", foo, 0);
        rb_define_method(mBar, "initialize", foo, 0);

        rb_define_method(mFoo, "baz", foo, 0);
        rb_define_singleton_method(mFoo, "baz", foo, 0);
        rb_define_method(mBar, "baz", foo, 0);
        rb_define_singleton_method(mBar, "baz", foo, 0);
      }
    eof
    expect(Registry.at('Foo#foo').docstring).to eq 'Foo bar!'
    expect(Registry.at('Foo.foo').docstring).to eq 'Foo bar!'
    expect(Registry.at('Foo::Bar#foo').docstring).to be_empty
    expect(Registry.at('Foo::Bar.foo').docstring).to be_empty
    expect(Registry.at('Foo#initialize').docstring).to eq 'Foo bar!'
    expect(Registry.at('Foo::Bar#initialize').docstring).to eq 'Foo bar!'
    expect(Registry.at('Foo#baz').docstring).to be_empty
    expect(Registry.at('Foo.baz').docstring).to be_empty
    expect(Registry.at('Foo::Bar#baz').docstring).to eq 'Foo bar!'
    expect(Registry.at('Foo::Bar.baz').docstring).to be_empty
  end

  it "recognizes core Ruby classes and modules provided by ruby.h" do
    parse_init <<-eof
      rb_define_method(rb_cFixnum, "popcount", fix_popcount, 0);
      rb_define_private_method(rb_mKernel, "pp", obj_pp, 0);
      rb_define_method(rb_mEnumerable, "to_hash", enum_to_hash, 0);
    eof
    expect(Registry.at('Fixnum').type).to eq :class
    expect(Registry.at('Fixnum#popcount').type).to eq :method
    expect(Registry.at('Object').type).to eq :class
    # Methods defined on Kernel are treated as if they were defined on Object
    expect(Registry.at('Object#pp').type).to eq :method
    expect(Registry.at('Enumerable').type).to eq :module
    expect(Registry.at('Enumerable#to_hash').type).to eq :method
  end
end
