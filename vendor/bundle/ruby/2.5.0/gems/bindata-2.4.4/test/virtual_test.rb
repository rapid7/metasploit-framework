#!/usr/bin/env ruby

require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

describe BinData::Virtual do
  let(:stream) { StringIO.new "abcdefghij" }

  it "must not read from any stream" do
    BinData::Virtual.read(stream)
    stream.pos.must_equal 0
  end

  it "must not write to a stream" do
    obj = BinData::Virtual.new
    obj.to_binary_s.must_equal_binary ""
  end

  it "occupies no space" do
    obj = BinData::Virtual.new
    obj.num_bytes.must_equal 0
  end

  it "asserts on #read" do
    data = []
    obj = BinData::Virtual.new(assert: -> { data << 1; true })

    obj.read ""
    data.must_equal [1]
  end

  it "asserts on #assign" do
    data = []
    obj = BinData::Virtual.new(assert: -> { data << 1; true })

    obj.assign("foo")
    data.must_equal [1]
  end

  it "assigns a value" do
    obj = BinData::Virtual.new(3)
    obj.must_equal 3
  end

  it "accepts the :value parameter" do
    obj = BinData::Virtual.new(value: 3)
    obj.must_equal 3
  end
end
