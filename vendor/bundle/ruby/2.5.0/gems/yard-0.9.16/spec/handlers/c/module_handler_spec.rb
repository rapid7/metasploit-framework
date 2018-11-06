# frozen_string_literal: true
require File.dirname(__FILE__) + "/spec_helper"

RSpec.describe YARD::Handlers::C::ClassHandler do
  it "registers modules" do
    parse_init 'mFoo = rb_define_module("Foo");'
    expect(Registry.at('Foo').type).to eq :module
  end

  it "registers classes under namespaces" do
    parse_init <<-EOF
      mBar = rb_define_module("Bar");
      mFoo = rb_define_module_under(mBar, "Foo");
    EOF
    expect(Registry.at('Bar::Foo').type).to eq :module
  end

  it "remembers symbol defined with class" do
    parse_init(<<-eof)
      cXYZ = rb_define_module("Foo");
      rb_define_method(cXYZ, "bar", bar, 0);
    eof
    expect(Registry.at('Foo').type).to eq :module
    expect(Registry.at('Foo#bar')).not_to be nil
  end

  it "does not associate declaration comments as module docstring" do
    parse_init(<<-eof)
      /* Docstring! */
      mFoo = rb_define_module("Foo");
    eof
    expect(Registry.at('Foo').docstring).to be_blank
  end

  it "associates a file with the declaration" do
    parse_init(<<-eof)
      mFoo = rb_define_module("Foo");
    eof
    expect(Registry.at('Foo').file).to eq '(stdin)'
    expect(Registry.at('Foo').line).to eq 2
  end

  it "resolves namespace variable names across multiple files" do
    parse_multi_file_init(
      'mBar = rb_define_module_under(mFoo, "Bar");',
      'mFoo = rb_define_module("Foo");'
    )

    expect(Registry.at('Foo::Bar').type).to eq :module
  end

  it "raises undoc error if a class is defined under a namespace that cannot be resolved" do
    with_parser(:c) do
      undoc_error <<-eof
        void Init_Foo() {
          mFoo = rb_define_class_under(invalid, "Foo", rb_cObject);
        }
      eof
    end
  end unless ENV['LEGACY']

  it "raises undoc error if a module is defined under a namespace that cannot be resolved" do
    with_parser(:c) do
      undoc_error <<-eof
        void Init_Foo() {
          mFoo = rb_define_module_under(invalid, "Foo");
        }
      eof
    end
  end unless ENV['LEGACY']
end
