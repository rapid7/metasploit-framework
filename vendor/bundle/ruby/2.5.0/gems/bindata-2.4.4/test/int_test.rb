#!/usr/bin/env ruby

require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

module AllIntegers

  def test_have_correct_num_bytes
    all_classes do |int_class|
      int_class.new.num_bytes.must_equal @nbytes
    end
  end

  def test_have_a_sensible_value_of_zero
    all_classes do |int_class|
      int_class.new.must_equal 0
    end
  end

  def test_avoid_underflow
    all_classes do |int_class|
      subject = int_class.new
      subject.assign(min_value - 1)

      subject.must_equal min_value
    end
  end

  def test_avoid_overflow
    all_classes do |int_class|
      subject = int_class.new
      subject.assign(max_value + 1)

      subject.must_equal max_value
    end
  end

  def test_assign_values
    all_classes do |int_class|
      subject = int_class.new
      test_int = gen_test_int
      subject.assign(test_int)

      subject.must_equal test_int
    end
  end

  def test_assign_values_from_other_int_objects
    all_classes do |int_class|
      src = int_class.new
      src.assign(gen_test_int)

      subject = int_class.new
      subject.assign(src)
      subject.must_equal src
    end
  end

  def test_symmetrically_read_and_write_a_positive_number
    all_classes do |int_class|
      subject = int_class.new
      subject.assign(gen_test_int)

      subject.value_read_from_written.must_equal subject
    end
  end

  def test_symmetrically_read_and_write_a_negative_number
    all_classes do |int_class|
      if @signed
        subject = int_class.new
        subject.assign(-gen_test_int)

        subject.value_read_from_written.must_equal subject
      end
    end
  end

  def test_convert_a_positive_number_to_string
    all_classes do |int_class|
      val = gen_test_int

      subject = int_class.new
      subject.assign(val)

      subject.to_binary_s.must_equal_binary int_to_binary_str(val)
    end
  end

  def test_convert_a_negative_number_to_string
    all_classes do |int_class|
      if @signed
        val = -gen_test_int

        subject = int_class.new
        subject.assign(val)

        subject.to_binary_s.must_equal_binary int_to_binary_str(val)
      end
    end
  end

  def all_classes(&block)
    @ints.each_pair do |int_class, nbytes|
      @nbytes = nbytes
      yield int_class
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
      (1 << (@nbytes * 8 - 1)) - 1
    else
      (1 << (@nbytes * 8)) - 1
    end
  end

  def gen_test_int
    # resulting int is guaranteed to be +ve for signed or unsigned integers
    (0 ... @nbytes).inject(0) { |val, i| (val << 8) | ((val + 0x11) % 0x100) }
  end

  def int_to_binary_str(val)
    str = "".force_encoding(Encoding::BINARY)
    v = val & ((1 << (@nbytes * 8)) - 1)
    @nbytes.times do
      str.concat(v & 0xff)
      v >>= 8
    end
    (@endian == :little) ? str : str.reverse
  end

  def create_mapping_of_class_to_nbits(endian, signed)
    base = signed ? "Int" : "Uint"
    endian_str = (endian == :little) ? "le" : "be"

    result = {}
    result[BinData.const_get("#{base}8")] = 1
    (1 .. 20).each do |nbytes|
      nbits = nbytes * 8
      class_name = "#{base}#{nbits}#{endian_str}"
      result[BinData.const_get(class_name)] = nbytes
    end

    result
  end
end

describe "All signed big endian integers" do
  include AllIntegers

  before do
    @endian = :big
    @signed = true
    @ints = create_mapping_of_class_to_nbits(@endian, @signed)
  end
end

describe "All unsigned big endian integers" do
  include AllIntegers

  before do
    @endian = :big
    @signed = false
    @ints = create_mapping_of_class_to_nbits(@endian, @signed)
  end
end

describe "All signed little endian integers" do
  include AllIntegers

  before do
    @endian = :little
    @signed = true
    @ints = create_mapping_of_class_to_nbits(@endian, @signed)
  end
end

describe "All unsigned little endian integers" do
  include AllIntegers

  before do
    @endian = :little
    @signed = false
    @ints = create_mapping_of_class_to_nbits(@endian, @signed)
  end
end

describe "Custom defined integers" do
  it "fail unless bits are a multiple of 8" do
    lambda { BinData::Uint7le }.must_raise NameError

    lambda { BinData::Uint7be }.must_raise NameError

    lambda { BinData::Int7le }.must_raise NameError

    lambda { BinData::Int7be }.must_raise NameError
  end
end
