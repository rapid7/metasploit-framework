#!/usr/bin/env ruby

require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

class ExampleSingle < BinData::BasePrimitive
  def self.io_with_value(val)
    StringIO.new([val].pack("V"))
  end

  private

  def value_to_binary_string(val)
    [val].pack("V")
  end

  def read_and_return_value(io)
    io.readbytes(4).unpack("V").at(0)
  end

  def sensible_default
    0
  end
end

describe BinData::BasePrimitive do
  it "is not registered" do
    lambda {
      BinData::RegisteredClasses.lookup("BasePrimitive")
    }.must_raise BinData::UnRegisteredTypeError
  end
end

describe BinData::BasePrimitive, "all subclasses" do
  class SubClassOfBasePrimitive < BinData::BasePrimitive
    expose_methods_for_testing
  end

  let(:obj) { SubClassOfBasePrimitive.new }

  it "raise errors on unimplemented methods" do
    lambda { obj.value_to_binary_string(nil) }.must_raise NotImplementedError
    lambda { obj.read_and_return_value(nil) }.must_raise NotImplementedError
    lambda { obj.sensible_default }.must_raise NotImplementedError
  end
end

describe ExampleSingle do
  let(:obj) { ExampleSingle.new(5) }

  it "fails when assigning nil values" do
    lambda { obj.assign(nil) }.must_raise ArgumentError
  end

  it "sets and retrieves values" do
    obj.assign(7)
    obj.must_equal 7
  end

  it "sets and retrieves BinData::BasePrimitives" do
    obj.assign(ExampleSingle.new(7))
    obj.must_equal 7
  end

  it "responds to known methods" do
    obj.must_respond_to :num_bytes
  end

  it "responds to known methods in #snapshot" do
    obj.must_respond_to :div
  end

  it "does not respond to unknown methods in self or #snapshot" do
    obj.wont_respond_to :does_not_exist
  end

  it "behaves as #snapshot" do
    (obj + 1).must_equal 6
    (1 + obj).must_equal 6
  end

  it "is equal to other ExampleSingle" do
    obj.must_equal ExampleSingle.new(5)
  end

  it "is equal to raw values" do
    obj.must_equal 5
    5.must_equal obj
  end

  it "can be used as a hash key" do
    hash = {5 => 17}

    hash[obj].must_equal 17
  end

  it "is sortable" do
    [ExampleSingle.new(5), ExampleSingle.new(3)].sort.must_equal [3, 5]
  end
end

describe BinData::BasePrimitive, "after initialisation" do
  let(:obj) { ExampleSingle.new }

  it "does not allow both :initial_value and :value" do
    params = {initial_value: 1, value: 2}
    lambda { ExampleSingle.new(params) }.must_raise ArgumentError
  end

  it "initial state" do
    assert obj.clear?
    obj.value.must_equal 0
    obj.num_bytes.must_equal 4
  end

  it "has symmetric IO" do
    obj.assign(42)
    written = obj.to_binary_s

    ExampleSingle.read(written).must_equal 42
  end

  it "sets and retrieves values" do
    obj.value = 5
    obj.value.must_equal 5
  end

  it "is not clear after setting value" do
    obj.assign(5)
    refute obj.clear?
  end

  it "is not clear after reading" do
    obj.read("\x11\x22\x33\x44")
    refute obj.clear?
  end

  it "returns a snapshot" do
    obj.assign(5)
    obj.snapshot.must_equal 5
  end
end

describe BinData::BasePrimitive, "with :initial_value" do
  let(:obj) { ExampleSingle.new(initial_value: 5) }

  it "initial state" do
    obj.value.must_equal 5
  end

  it "forgets :initial_value after being set" do
    obj.assign(17)
    obj.wont_equal 5
  end

  it "forgets :initial_value after reading" do
    obj.read("\x11\x22\x33\x44")
    obj.wont_equal 5
  end

  it "remembers :initial_value after being cleared" do
    obj.assign(17)
    obj.clear
    obj.must_equal 5
  end
end

describe BinData::BasePrimitive, "with :value" do
  let(:obj) { ExampleSingle.new(value: 5) }
  let(:io)  { ExampleSingle.io_with_value(56) }

  it "initial state" do
    obj.value.must_equal 5
  end

  it "changes during reading" do
    obj.read(io)
    obj.stub :reading?, true do
      obj.must_equal 56
    end
  end

  it "does not change after reading" do
    obj.read(io)
    obj.must_equal 5
  end

  it "is unaffected by assigning" do
    obj.assign(17)
    obj.must_equal 5
  end
end

describe BinData::BasePrimitive, "asserting value" do
  let(:io) { ExampleSingle.io_with_value(12) }

  describe ":assert is non boolean" do
    it "asserts sensible value" do
      data = ExampleSingle.new(assert: 0)
      data.assert!
      data.value.must_equal 0
    end

    it "succeeds when assert is correct" do
      data = ExampleSingle.new(assert: 12)
      data.read(io)
      data.value.must_equal 12
    end

    it "fails when assert is incorrect" do
      data = ExampleSingle.new(assert: -> { 99 })
      lambda { data.read(io) }.must_raise BinData::ValidityError
    end
  end

  describe ":assert is boolean" do
    it "succeeds when assert is true" do
      data = ExampleSingle.new(assert: -> { value < 20 })
      data.read(io)
      data.value.must_equal 12
    end

    it "fails when assert is false" do
      data = ExampleSingle.new(assert: -> { value > 20 })
      lambda { data.read(io) }.must_raise BinData::ValidityError
    end
  end

  describe "assigning with :assert" do
    it "succeeds when assert is correct" do
      data = ExampleSingle.new(assert: 12)
      data.assign(12)
      data.value.must_equal 12
    end

    it "fails when assert is incorrect" do
      data = ExampleSingle.new(assert: 12)
      lambda { data.assign(99) }.must_raise BinData::ValidityError
    end
  end
end

describe BinData::BasePrimitive, ":asserted_value" do
  it "has :value" do
    data = ExampleSingle.new(asserted_value: -> { 12 })
    data.value.must_equal 12
  end

  describe "assigning with :assert" do
    it "succeeds when assert is correct" do
      data = ExampleSingle.new(asserted_value: -> { 12 })
      data.assign(12)
      data.value.must_equal 12
    end

    it "fails when assert is incorrect" do
      data = ExampleSingle.new(asserted_value: -> { 12 })
      lambda { data.assign(99) }.must_raise BinData::ValidityError
    end
  end
end

describe BinData::BasePrimitive do
  it "conforms to rule 1 for returning a value" do
    data = ExampleSingle.new(value: 5)
    data.must_equal 5
  end

  it "conforms to rule 2 for returning a value" do
    io = ExampleSingle.io_with_value(42)
    data = ExampleSingle.new(value: 5)
    data.read(io)

    data.stub :reading?, true do
      data.must_equal 42
    end
  end

  it "conforms to rule 3 for returning a value" do
    data = ExampleSingle.new(initial_value: 5)
    assert data.clear?
    data.must_equal 5
  end

  it "conforms to rule 4 for returning a value" do
    data = ExampleSingle.new(initial_value: 5)
    data.assign(17)
    refute data.clear?
    data.must_equal 17
  end

  it "conforms to rule 5 for returning a value" do
    data = ExampleSingle.new
    assert data.clear?
    data.must_equal 0
  end

  it "conforms to rule 6 for returning a value" do
    data = ExampleSingle.new
    data.assign(8)
    refute data.clear?
    data.must_equal 8
  end
end

