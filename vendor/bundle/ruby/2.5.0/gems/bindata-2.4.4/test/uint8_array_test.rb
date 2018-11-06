#!/usr/bin/env ruby

require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

describe BinData::Uint8Array, "when initialising" do
  it "with mutually exclusive parameters :initial_length and :read_until" do
    params = {initial_length: 5, read_until: :eof}
    lambda { BinData::Uint8Array.new(params) }.must_raise ArgumentError
  end

  it "with :read_until" do
    params = {read_until: :not_eof}
    lambda { BinData::Uint8Array.new(params) }.must_raise ArgumentError
  end

  it "with no parameters" do
    arr = BinData::Uint8Array.new
    arr.num_bytes.must_equal 0
  end
end

describe BinData::Uint8Array, "with :read_until" do
  it "reads until :eof" do
    arr = BinData::Uint8Array.new(read_until: :eof)
    arr.read("\xff\xfe\xfd\xfc")
    arr.must_equal([255, 254, 253, 252])
  end
end

describe BinData::Uint8Array, "with :initial_length" do
  it "reads" do
    arr = BinData::Uint8Array.new(initial_length: 3)
    arr.read("\xff\xfe\xfd\xfc")
    arr.must_equal([255, 254, 253])
  end
end

describe BinData::Uint8Array, "when assigning" do
  it "copies data" do
    arr = BinData::Uint8Array.new
    arr.assign([1, 2, 3])
    arr.must_equal([1, 2, 3])
  end
end
