#!/usr/bin/env ruby

require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

module FloatTest
  def test_num_bytes
    @obj.num_bytes.must_equal 4
  end

  def test_writing_then_reading
    @obj.value_read_from_written.must_be_close_to Math::PI, 0.000001
  end
end

module DoubleTest
  def test_num_bytes
    @obj.num_bytes.must_equal 8
  end

  def test_writing_then_reading
    @obj.value_read_from_written.must_be_close_to Math::PI, 0.0000000000000001
  end
end

describe "A FloatLe" do
  include FloatTest

  before do
    @obj = BinData::FloatLe.new(Math::PI)
  end

  it "#to_binary_s" do
    @obj.to_binary_s.must_equal_binary [Math::PI].pack('e')
  end
end

describe "A FloatBe" do
  include FloatTest

  before do
    @obj = BinData::FloatBe.new(Math::PI)
  end

  it "#to_binary_s" do
    @obj.to_binary_s.must_equal_binary [Math::PI].pack('g')
  end
end

describe "A DoubleLe" do
  include DoubleTest

  before do
    @obj = BinData::DoubleLe.new(Math::PI)
  end

  it "#to_binary_s" do
    @obj.to_binary_s.must_equal_binary [Math::PI].pack('E')
  end
end


describe "A DoubleBe" do
  include DoubleTest

  before do
    @obj = BinData::DoubleBe.new(Math::PI)
  end

  it "#to_binary_s" do
    @obj.to_binary_s.must_equal_binary [Math::PI].pack('G')
  end
end
