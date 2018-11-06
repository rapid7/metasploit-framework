#!/usr/bin/env ruby

require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

describe BinData::Skip, "when instantiating" do
  describe "with no mandatory parameters supplied" do
    it "raises an error" do
      args = {}
      lambda { BinData::Skip.new(args) }.must_raise ArgumentError
    end
  end
end

describe BinData::Skip, "with :length" do
  let(:obj) { BinData::Skip.new(length: 5) }
  let(:io) { StringIO.new("abcdefghij") }

  it "initial state" do
    obj.must_equal ""
    obj.to_binary_s.must_equal_binary "\000" * 5
  end

  it "skips bytes" do
    obj.read(io)
    io.pos.must_equal 5
  end

  it "has expected binary representation after setting value" do
    obj.assign("123")
    obj.to_binary_s.must_equal_binary "\000" * 5
  end

  it "has expected binary representation after reading" do
    obj.read(io)
    obj.to_binary_s.must_equal_binary "\000" * 5
  end
end

describe BinData::Skip, "with :to_abs_offset" do
  BinData::Struct.new(fields: [ [:skip, :f, { to_abs_offset: 5 } ] ])

  let(:skip_obj) { [:skip, :f, { to_abs_offset: 5 } ] }
  let(:io) { StringIO.new("abcdefghij") }

  it "reads skipping forward" do
    fields = [ skip_obj ]
    obj = BinData::Struct.new(fields: fields)
    obj.read(io)
    io.pos.must_equal 5
  end

  it "reads skipping in place" do
    fields = [ [:string, :a, { read_length: 5 }], skip_obj ]
    obj = BinData::Struct.new(fields: fields)
    obj.read(io)
    io.pos.must_equal 5
  end

  it "does not read skipping backwards" do
    fields = [ [:string, :a, { read_length: 10 }], skip_obj ]
    obj = BinData::Struct.new(fields: fields)

    lambda {
      obj.read(io)
    }.must_raise BinData::ValidityError
  end

  it "writes skipping forward" do
    fields = [ skip_obj ]
    obj = BinData::Struct.new(fields: fields)
    obj.to_binary_s.must_equal "\000\000\000\000\000"
  end

  it "reads skipping in place" do
    fields = [ [:string, :a, { value: "abcde" }], skip_obj ]
    obj = BinData::Struct.new(fields: fields)
    obj.to_binary_s.must_equal "abcde"
  end

  it "does not write skipping backwards" do
    fields = [ [:string, :a, { value: "abcdefghij" }], skip_obj ]
    obj = BinData::Struct.new(fields: fields)
    lambda {
      obj.to_binary_s
    }.must_raise BinData::ValidityError
  end
end

describe BinData::Skip, "with :until_valid" do
  let(:io) { StringIO.new("abcdefghij") }

  it "skips to valid match" do
    skip_obj = [:string, { read_length: 1, assert: "f" }]
    fields = [ [:skip, :s, { until_valid: skip_obj }] ]
    obj = BinData::Struct.new(fields: fields)
    obj.read(io)
    io.pos.must_equal 5
  end

  it "doesn't skip when validator doesn't assert" do
    skip_obj = [:string, { read_length: 1 }]
    fields = [ [:skip, :s, { until_valid: skip_obj }] ]
    obj = BinData::Struct.new(fields: fields)
    obj.read(io)
    io.pos.must_equal 0
  end

  it "raises EOFError when no match" do
    skip_obj = [:string, { read_length: 1, assert: "X" }]
    fields = [ [:skip, :s, { until_valid: skip_obj }] ]
    obj = BinData::Struct.new(fields: fields)
    lambda {
      obj.read(io)
    }.must_raise EOFError
  end

  it "raises IOError when validator reads beyond stream" do
    skip_obj = [:string, { read_length: 30 }]
    fields = [ [:skip, :s, { until_valid: skip_obj }] ]
    obj = BinData::Struct.new(fields: fields)
    lambda {
      obj.read(io)
    }.must_raise IOError
  end

  class DSLSkip < BinData::Record
    skip :s do
      string read_length: 1, assert: "f"
    end
    string :a, read_length: 1
  end

  it "uses block form" do
    obj = DSLSkip.read(io)
    obj.a.must_equal "f"
  end
end
