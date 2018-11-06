# frozen_string_literal: true
require File.dirname(__FILE__) + "/spec_helper"

RSpec.describe YARD::Handlers::C::AttributeHandler do
  def run(read, write, commented = nil)
    parse <<-eof
      /* FOO */
      VALUE foo(VALUE x) { int value = x; }
      void Init_Foo() {
        rb_cFoo = rb_define_class("Foo", rb_cObject);
        #{commented ? '/*' : ''}
          rb_define_attr(rb_cFoo, "foo", #{read}, #{write});
        #{commented ? '*/' : ''}
      }
    eof
  end

  it "handles readonly attribute (rb_define_attr)" do
    run(1, 0)
    expect(Registry.at('Foo#foo')).to be_reader
    expect(Registry.at('Foo#foo=')).to be nil
  end

  it "handles writeonly attribute (rb_define_attr)" do
    run(0, 1)
    expect(Registry.at('Foo#foo')).to be nil
    expect(Registry.at('Foo#foo=')).to be_writer
  end

  it "handles readwrite attribute (rb_define_attr)" do
    run(1, 1)
    expect(Registry.at('Foo#foo')).to be_reader
    expect(Registry.at('Foo#foo=')).to be_writer
  end

  it "handles commented writeonly attribute (/* rb_define_attr */)" do
    run(1, 1, true)
    expect(Registry.at('Foo#foo')).to be_reader
    expect(Registry.at('Foo#foo=')).to be_writer
  end
end
