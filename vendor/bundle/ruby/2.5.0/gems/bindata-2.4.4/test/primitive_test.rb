#!/usr/bin/env ruby

require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

describe BinData::Primitive do
  it "is not registered" do
    lambda {
      BinData::RegisteredClasses.lookup("Primitive")
    }.must_raise BinData::UnRegisteredTypeError
  end
end

describe BinData::Primitive, "all subclasses" do
  class SubClassOfPrimitive < BinData::Primitive
    expose_methods_for_testing
  end

  let(:obj) { SubClassOfPrimitive.new }

  it "raise errors on unimplemented methods" do
    lambda { obj.set(nil) }.must_raise NotImplementedError
    lambda { obj.get      }.must_raise NotImplementedError
  end
end

describe BinData::Primitive, "when defining with errors" do
  it "fails on non registered types" do
    lambda {
      class BadTypePrimitive < BinData::Primitive
        non_registered_type :a
      end
    }.must_raise_on_line TypeError, 2, "unknown type 'non_registered_type' in BadTypePrimitive"
  end

  it "fails on duplicate names" do
    lambda {
      class DuplicateNamePrimitive < BinData::Primitive
        int8 :a
        int8 :b
        int8 :a
      end
    }.must_raise_on_line SyntaxError, 4, "duplicate field 'a' in DuplicateNamePrimitive"
  end

  it "fails when field name shadows an existing method" do
    lambda {
      class ExistingNamePrimitive < BinData::Primitive
        int8 :object_id
      end
    }.must_raise_on_line NameError, 2, "field 'object_id' shadows an existing method in ExistingNamePrimitive"
  end

  it "fails on unknown endian" do
    lambda {
      class BadEndianPrimitive < BinData::Primitive
        endian 'a bad value'
      end
    }.must_raise_on_line ArgumentError, 2, "unknown value for endian 'a bad value' in BadEndianPrimitive"
  end
end

describe BinData::Primitive do
  class PrimitiveWithEndian < BinData::Primitive
    endian :little
    int16 :a
    def get; self.a; end
    def set(v); self.a = v; end
  end

  let(:obj) { PrimitiveWithEndian.new }

  it "assigns value" do
    obj.value = 5
    obj.value.must_equal 5
  end

  it "produces binary string" do
    obj.assign(5)
    obj.to_binary_s.must_equal_binary "\x05\x00"
  end

  it "reads value" do
    obj.read("\x00\x01")
    obj.must_equal 0x100
  end

  it "accepts standard parameters" do
    obj = PrimitiveWithEndian.new(initial_value: 2)
    obj.to_binary_s.must_equal_binary "\x02\x00"
  end

  it "returns num_bytes" do
    obj.num_bytes.must_equal 2
  end

  it "raises error on missing methods" do
    lambda {
      obj.does_not_exist
    }.must_raise NoMethodError
  end

  it "uses read value whilst reading" do
    obj = PrimitiveWithEndian.new(value: 2)
    obj.read "\x05\x00"
    obj.must_equal 2

    obj.stub :reading?, true do
      obj.must_equal 5
    end
  end

  it "behaves as primitive" do
    obj.assign(5)
    (2 + obj).must_equal 7
  end
end

describe BinData::Primitive, "requiring custom parameters" do
  class PrimitiveWithCustom < BinData::Primitive
    int8 :a, initial_value: :iv
    def get; self.a; end
    def set(v); self.a = v; end
  end

  it "passes parameters correctly" do
    obj = PrimitiveWithCustom.new(iv: 5)
    obj.must_equal 5
  end
end

describe BinData::Primitive, "with custom mandatory parameters" do
  class MandatoryPrimitive < BinData::Primitive
    mandatory_parameter :arg1

    uint8 :a, value: :arg1
    def get; self.a; end
    def set(v); self.a = v; end
  end

  it "raises error if mandatory parameter is not supplied" do
    lambda { MandatoryPrimitive.new }.must_raise ArgumentError
  end

  it "uses mandatory parameter" do
    obj = MandatoryPrimitive.new(arg1: 5)
    obj.must_equal 5
  end
end

describe BinData::Primitive, "with custom default parameters" do
  class DefaultPrimitive < BinData::Primitive
    default_parameter arg1: 5

    uint8 :a, value: :arg1
    def get; self.a; end
    def set(v); self.a = v; end
  end

  it "uses default parameter" do
    obj = DefaultPrimitive.new
    obj.must_equal 5
  end

  it "overrides default parameter" do
    obj = DefaultPrimitive.new(arg1: 7)
    obj.must_equal 7
  end
end

describe BinData::Primitive, "subclassed with default parameter" do
  class ParentDerivedPrimitive < BinData::Primitive
    uint16be :a
    def get; self.a; end
    def set(v); self.a = v; end
  end

  class ChildDerivedPrimitive < ParentDerivedPrimitive
    default_parameter initial_value: 5
  end

  it "overrides initial_value" do
    a = ChildDerivedPrimitive.new(initial_value: 7)
    a.to_binary_s.must_equal_binary "\000\007"
  end

  it "uses default parameter" do
    a = ChildDerivedPrimitive.new
    a.to_binary_s.must_equal_binary "\000\005"
  end
end

describe BinData::Primitive, "with mutating #get and #set" do
  class MutatingPrimitive < BinData::Primitive
    uint16le :a
    def get; self.a; end
    def set(v); self.a = v.abs; end
  end

  it "#assign applies mutator" do
    obj = MutatingPrimitive.new
    obj.assign(-50)
    obj.snapshot.must_equal 50
  end

  it "#to_binary_s applies mutator" do
    obj = MutatingPrimitive.new
    obj.assign(-50)
    obj.to_binary_s.must_equal_binary "\062\000"
  end
end
