# frozen_string_literal: true
require File.dirname(__FILE__) + "/spec_helper"

RSpec.describe YARD::Handlers::C::ClassHandler do
  it "registers classes" do
    parse_init 'cFoo = rb_define_class("Foo", rb_cObject);'
    expect(Registry.at('Foo').type).to eq :class
  end

  it "registers classes under namespaces" do
    parse_init <<-EOF
      cBar = rb_define_class("Bar", rb_cObject);
      cFoo = rb_define_class_under( cBar, "Foo", rb_cBaz );
    EOF
    expect(Registry.at('Bar::Foo').type).to eq :class
    expect(Registry.at('Bar::Foo').superclass.path).to eq 'Baz'
  end

  it "remembers symbol defined with class" do
    parse_init(<<-eof)
      cXYZ = rb_define_class("Foo", rb_cObject);
      rb_define_method(cXYZ, "bar", bar, 0);
    eof
    expect(Registry.at('Foo').type).to eq :class
    expect(Registry.at('Foo#bar')).not_to be nil
  end

  it "looks up superclass symbol name" do
    parse_init(<<-eof)
      cXYZ = rb_define_class("Foo", rb_cObject);
      cBar = rb_define_class("Bar", cXYZ);
    eof
    expect(Registry.at('Bar').superclass).to eq Registry.at('Foo')
  end

  it "uses superclass symbol name as proxy if not found" do
    parse_init(<<-eof)
      // cXYZ = rb_define_class("Foo", rb_cObject);
      cBar = rb_define_class("Bar", cXYZ);
    eof
    expect(Registry.at('Bar').superclass).to eq P('XYZ')
  end

  it "does not associate declaration comments as class docstring" do
    parse_init(<<-eof)
      /* Docstring! */
      cFoo = rb_define_class("Foo", cObject);
    eof
    expect(Registry.at('Foo').docstring).to be_blank
  end

  it "associates a file with the declaration" do
    parse_init(<<-eof)
      cFoo = rb_define_class("Foo", cObject);
    eof
    expect(Registry.at('Foo').file).to eq '(stdin)'
    expect(Registry.at('Foo').line).to eq 2
  end

  it "properly handles Proxy superclasses" do
    parse_init <<-eof
      mFoo = rb_define_module("Foo");
      cBar = rb_define_class_under(mFoo, "Bar", rb_cBar);
    eof
    expect(Registry.at('Foo::Bar').type).to eq :class
    expect(Registry.at('Foo::Bar').superclass).to eq P('Bar')
    expect(Registry.at('Foo::Bar').superclass.type).to eq :class
  end

  it "resolves namespace variable names across multiple files" do
    parse_multi_file_init(
      'cBar = rb_define_class_under(cFoo, "Bar", rb_cObject);',
      'cFoo = rb_define_class("Foo", rb_cObject);'
    )

    expect(Registry.at('Foo::Bar').type).to eq :class
  end
end
