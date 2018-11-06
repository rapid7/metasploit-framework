#!/usr/bin/env ruby

require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

describe BinData::Buffer, "when instantiating" do
  describe "with no mandatory parameters supplied" do
    it "raises an error" do
      args = {}
      lambda { BinData::Buffer.new(args) }.must_raise ArgumentError
    end
  end

  describe "with some but not all mandatory parameters supplied" do
    it "raises an error" do
      args = {length: 3}
      lambda { BinData::Buffer.new(args) }.must_raise ArgumentError
    end
  end

  it "fails if a given type is unknown" do
    args = {type: :does_not_exist, length: 3}
    lambda { BinData::Buffer.new(args) }.must_raise BinData::UnRegisteredTypeError
  end

  it "accepts BinData::Base as :type" do
    obj = BinData::Int8.new(initial_value: 5)
    array = BinData::Buffer.new(type: obj, length: 3)
    array.must_equal 5
  end
end

describe BinData::Buffer, "subclassed with a single type" do
  class IntBuffer < BinData::Buffer
    endian :big
    default_parameter length: 5

    uint16
  end

  it "behaves as type" do
    obj = IntBuffer.new(3)
    obj.must_equal 3
  end

  it "reads data" do
    obj = IntBuffer.read "\001\002\003\004\005"
    obj.must_equal 0x0102
  end

  it "writes data" do
    obj = IntBuffer.new(3)
    obj.to_binary_s.must_equal_binary "\000\003\000\000\000"
  end

  it "has total num_bytes" do
    obj = IntBuffer.new
    assert obj.clear?
    obj.num_bytes.must_equal 5
  end

  it "has raw_num_bytes" do
    obj = IntBuffer.new
    assert obj.clear?
    obj.raw_num_bytes.must_equal 2
  end
end

describe BinData::Buffer, "subclassed with multiple types" do
  class TupleBuffer < BinData::Buffer
    endian :big
    default_parameter length: 5

    uint16 :a
    uint16 :b
  end

  it "behaves as type" do
    obj = TupleBuffer.new(a: 1, b: 2)
    obj.a.must_equal 1
    obj.b.must_equal 2
  end

  it "has total num_bytes" do
    obj = TupleBuffer.new
    obj.num_bytes.must_equal 5
  end

  it "has raw_num_bytes" do
    obj = TupleBuffer.new
    obj.raw_num_bytes.must_equal 4
  end

  it "reads data" do
    obj = TupleBuffer.read "\001\002\003\004\005"
    obj.a.must_equal 0x0102
    obj.b.must_equal 0x0304
  end

  it "writes data" do
    obj = TupleBuffer.new(a: 1, b: 2)
    obj.to_binary_s.must_equal_binary "\000\001\000\002\000"
  end
end

describe BinData::Buffer, "inside a Record" do
  class BufferRecord < BinData::Record
    endian :little

    uint16 :buffer_length, value: -> { 2 * list.length + 1 }
    buffer :list, length: :buffer_length do
      array type: :int16, read_until: :eof
    end
    string :footer, read_length: 2, asserted_value: "ZZ"
  end

  it "reads" do
    obj = BufferRecord.read "\007\000\004\000\005\000\006\000\000ZZ"
    obj.list.must_equal [4, 5, 6]
  end

  it "writes" do
    obj = BufferRecord.new(list: [1, 2, 3, 4, 5])
    obj.to_binary_s.must_equal_binary "\013\000\001\000\002\000\003\000\004\000\005\000\000ZZ"
  end
end

describe BinData::Buffer, "nested buffers" do
  class NestedBufferRecord < BinData::Record
    buffer :a, length: 10 do
      buffer :aa, length: 5 do
        string read_length: 5
      end
      buffer :bb, length: 20 do
        string read_length: 5
      end
    end
    string :b, read_length: 5
  end

  it "restricts large nested buffer" do
    obj = NestedBufferRecord.read "abcdefghijklmnopqrst"
    obj.a.aa.must_equal "abcde"
    obj.a.bb.must_equal "fghij"
    obj.b.must_equal "klmno"
  end

  it "restricts oversize writes" do
    obj = NestedBufferRecord.new
    obj.a.aa = "abcdefghij"
    obj.a.bb = "ABCDEFGHIJ"
    obj.b = "12345"

    obj.to_binary_s.must_equal_binary "abcdeABCDE12345"
  end
end

