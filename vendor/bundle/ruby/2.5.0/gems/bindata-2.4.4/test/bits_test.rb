#!/usr/bin/env ruby

require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

module AllBitfields

  def test_has_a_sensible_value_of_zero
    all_objects do |obj, nbits|
      obj.must_equal 0
    end
  end

  def test_avoids_underflow
    all_objects do |obj, nbits|
      obj.assign(min_value - 1)
      obj.must_equal min_value
    end
  end

  def test_avoids_overflow
    all_objects do |obj, nbits|
      obj.assign(max_value + 1)
      obj.must_equal max_value
    end
  end

  def test_assign_values
    all_objects do |obj, nbits|
      some_values_within_range.each do |val|
        obj.assign(val)
        obj.must_equal val
      end
    end
  end

  def test_assign_values_from_other_bit_objects
    all_objects do |obj, nbits|
      some_values_within_range.each do |val|
        obj.assign(obj.new(val))
        obj.must_equal val
      end
    end
  end

  def test_symmetrically_read_and_write
    all_objects do |obj, nbits|
      some_values_within_range.each do |val|
        obj.assign(val)
        other = obj.new
        other.read(obj.to_binary_s)
        other.must_equal obj
      end
    end
  end

  def all_objects(&block)
    @bits.each do |obj, nbits|
      @nbits = nbits
      yield obj, nbits
    end
  end

  def min_value
    if @signed
      -max_value - 1
    else
      0
    end
  end

  def max_value
    if @signed
      (1 << (@nbits - 1)) - 1
    else
      (1 << @nbits) - 1
    end
  end

  def some_values_within_range
    lo  = min_value + 1
    mid = (min_value + max_value) / 2
    hi  = max_value - 1

    [lo, mid, hi].select { |val| value_within_range?(val) }
  end

  def value_within_range?(val)
    (min_value .. max_value).include?(val)
  end
end

def generate_bit_classes_to_test(endian, signed)
  bits = []
  if signed
    base  = "Sbit"
    start = 2
  else
    base  = "Bit"
    start = 1
  end

  (start .. 64).each do |nbits|
    name = "#{base}#{nbits}"
    name << "le" if endian == :little
    obj = BinData.const_get(name).new
    bits << [obj, nbits]
  end

  (start .. 64).each do |nbits|
    name = "#{base}"
    name << "Le" if endian == :little
    obj = BinData.const_get(name).new(nbits: nbits)
    bits << [obj, nbits]
  end

  bits
end

describe "Unsigned big endian bitfields" do
  include AllBitfields

  before do
    @signed = false
    @bits = generate_bit_classes_to_test(:big, @signed)
  end

  it "read big endian values" do
    all_objects do |obj, nbits|
      nbytes = (nbits + 7) / 8
      str = [0b1000_0000].pack("C") + "\000" * (nbytes - 1)

      obj.read(str)
      obj.must_equal 1 << (nbits - 1)
    end
  end
end

describe "Signed big endian bitfields" do
  include AllBitfields

  before do
    @signed = true
    @bits = generate_bit_classes_to_test(:big, @signed)
  end

  it "read big endian values" do
    all_objects do |obj, nbits|
      nbytes = (nbits + 7) / 8
      str = [0b0100_0000].pack("C") + "\000" * (nbytes - 1)

      obj.read(str)
      obj.must_equal 1 << (nbits - 2)
    end
  end
end

describe "Unsigned little endian bitfields" do
  include AllBitfields

  before do
    @signed = false
    @bits = generate_bit_classes_to_test(:little, @signed)
  end

  it "read little endian values" do
    all_objects do |obj, nbits|
      nbytes = (nbits + 7) / 8
      str = [0b0000_0001].pack("C") + "\000" * (nbytes - 1)

      obj.read(str)
      obj.must_equal 1
    end
  end
end

describe "Signed little endian bitfields" do
  include AllBitfields

  before do
    @signed = true
    @bits = generate_bit_classes_to_test(:little, @signed)
  end

  it "read little endian values" do
    all_objects do |obj, nbits|
      nbytes = (nbits + 7) / 8
      str = [0b0000_0001].pack("C") + "\000" * (nbytes - 1)

      obj.read(str)
      obj.must_equal 1
    end
  end
end

describe "Bits of size 1" do
  let(:bit_classes) { [BinData::Bit1, BinData::Bit1le] }

  it "accept true as value" do
    bit_classes.each do |bit_class|
      obj = bit_class.new
      obj.assign(true)
      obj.must_equal 1
    end
  end

  it "accept false as value" do
    bit_classes.each do |bit_class|
      obj = bit_class.new
      obj.assign(false)
      obj.must_equal 0
    end
  end

  it "accept nil as value" do
    bit_classes.each do |bit_class|
      obj = bit_class.new
      obj.assign(nil)
      obj.must_equal 0
    end
  end

  it "must not be signed" do
    lambda {
      BinData::Sbit1
    }.must_raise RuntimeError

    lambda {
      BinData::Sbit1le
    }.must_raise RuntimeError
  end
end
