#!/usr/bin/env ruby

require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

describe BinData::Registry do
  A = Class.new
  B = Class.new
  C = Class.new
  D = Class.new

  let(:r) { BinData::Registry.new }

  it "lookups registered names" do
    r.register('ASubClass', A)
    r.register('AnotherSubClass', B)

    r.lookup('ASubClass').must_equal A
    r.lookup('a_sub_class').must_equal A
    r.lookup('AnotherSubClass').must_equal B
    r.lookup('another_sub_class').must_equal B
  end

  it "does not lookup unregistered names" do
    lambda {
      r.lookup('a_non_existent_sub_class')
    }.must_raise BinData::UnRegisteredTypeError
  end

  it "unregisters names" do
    r.register('ASubClass', A)
    r.unregister('ASubClass')

    lambda {
      r.lookup('ASubClass')
    }.must_raise BinData::UnRegisteredTypeError
  end

  it "allows overriding of registered classes" do
    r.register('A', A)
    r.register('A', B)

    r.lookup('a').must_equal B
  end

  it "converts CamelCase to underscores" do
    r.underscore_name('CamelCase').must_equal 'camel_case'
  end

  it "converts adjacent caps camelCase to underscores" do
    r.underscore_name('XYZCamelCase').must_equal 'xyz_camel_case'
  end

  it "ignores the outer nestings of classes" do
    r.underscore_name('A::B::C').must_equal 'c'
  end
end

describe BinData::Registry, "with numerics" do
  let(:r) { BinData::RegisteredClasses }

  it "lookup integers with endian" do
    r.lookup("int24", {endian: :big}).to_s.must_equal "BinData::Int24be"
    r.lookup("int24", {endian: :little}).to_s.must_equal "BinData::Int24le"
    r.lookup("uint24", {endian: :big}).to_s.must_equal "BinData::Uint24be"
    r.lookup("uint24", {endian: :little}).to_s.must_equal "BinData::Uint24le"
  end

  it "does not lookup integers without endian" do
    lambda {
      r.lookup("int24")
    }.must_raise BinData::UnRegisteredTypeError
  end

  it "provides a nice error message when endian is omitted" do
    begin
      r.lookup("int24")
    rescue BinData::UnRegisteredTypeError => e
      e.message.must_equal "int24, do you need to specify endian?"
    end
  end

  it "does not lookup non byte based integers" do
    lambda {
      r.lookup("int3")
    }.must_raise BinData::UnRegisteredTypeError
    lambda {
      r.lookup("int3", {endian: :big})
    }.must_raise BinData::UnRegisteredTypeError
    lambda {
      r.lookup("int3", {endian: :little})
    }.must_raise BinData::UnRegisteredTypeError
  end

  it "lookup floats with endian" do
    r.lookup("float", {endian: :big}).to_s.must_equal "BinData::FloatBe"
    r.lookup("float", {endian: :little}).to_s.must_equal "BinData::FloatLe"
    r.lookup("double", {endian: :big}).to_s.must_equal "BinData::DoubleBe"
    r.lookup("double", {endian: :little}).to_s.must_equal "BinData::DoubleLe"
  end

  it "lookup bits" do
    r.lookup("bit5").to_s.must_equal "BinData::Bit5"
    r.lookup("sbit5").to_s.must_equal "BinData::Sbit5"
    r.lookup("bit6le").to_s.must_equal "BinData::Bit6le"
  end

  it "lookup bits by ignoring endian" do
    r.lookup("bit2", {endian: :big}).to_s.must_equal "BinData::Bit2"
    r.lookup("bit3le", {endian: :big}).to_s.must_equal "BinData::Bit3le"
    r.lookup("bit2", {endian: :little}).to_s.must_equal "BinData::Bit2"
    r.lookup("bit3le", {endian: :little}).to_s.must_equal "BinData::Bit3le"
  end

  it "lookup signed bits by ignoring endian" do
    r.lookup("sbit2", {endian: :big}).to_s.must_equal "BinData::Sbit2"
    r.lookup("sbit3le", {endian: :big}).to_s.must_equal "BinData::Sbit3le"
    r.lookup("sbit2", {endian: :little}).to_s.must_equal "BinData::Sbit2"
    r.lookup("sbit3le", {endian: :little}).to_s.must_equal "BinData::Sbit3le"
  end
end

describe BinData::Registry, "with endian specific types" do
  let(:r) { BinData::Registry.new }

  before do
    r.register('a_le', A)
    r.register('b_be', B)
  end
  
  it "lookup little endian types" do
    r.lookup('a', {endian: :little}).must_equal A
  end

  it "lookup big endian types" do
    r.lookup('b', {endian: :big}).must_equal B
  end

  it "does not lookup types with non existent endian" do
    lambda {
      r.lookup('a', {endian: :big})
    }.must_raise BinData::UnRegisteredTypeError
  end

  it "lookup prefers exact type" do
    r.register('c', C)
    r.register('c_le', D)

    r.lookup('c', {endian: :little}).must_equal C
  end
end

describe BinData::Registry, "with search_prefix" do
  let(:r) { BinData::Registry.new }

  before do
    r.register('a_f', A)
    r.register('b_f', B)
  end

  it "lookup single search_prefix" do
    r.lookup('f', {search_prefix: :a}).must_equal A
  end

  it "lookup single search_prefix with endian" do
    r.lookup('f', {search_prefix: :a, endian: :little}).must_equal A
  end

  it "lookup multiple search_prefix" do
    r.lookup('f', {search_prefix: [:x, :a]}).must_equal A
  end

  it "lookup first match in search_prefix" do
    r.lookup('f', {search_prefix: [:a, :b]}).must_equal A
  end
end
