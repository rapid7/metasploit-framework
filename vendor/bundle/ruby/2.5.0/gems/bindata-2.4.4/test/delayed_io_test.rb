#!/usr/bin/env ruby

require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

describe BinData::DelayedIO, "when instantiating" do
  describe "with no mandatory parameters supplied" do
    it "raises an error" do
      args = {}
      lambda { BinData::DelayedIO.new(args) }.must_raise ArgumentError
    end
  end

  describe "with some but not all mandatory parameters supplied" do
    it "raises an error" do
      args = {read_abs_offset: 3}
      lambda { BinData::DelayedIO.new(args) }.must_raise ArgumentError
    end
  end

  it "fails if a given type is unknown" do
    args = {type: :does_not_exist, length: 3}
    lambda { BinData::DelayedIO.new(args) }.must_raise BinData::UnRegisteredTypeError
  end

  it "accepts BinData::Base as :type" do
    obj = BinData::Int8.new(initial_value: 5)
    array = BinData::DelayedIO.new(type: obj, read_abs_offset: 3)
    array.must_equal 5
  end
end

describe BinData::DelayedIO, "subclassed with a single type" do
  class IntDelayedIO < BinData::DelayedIO
    endian :big
    default_parameter read_abs_offset: 5

    uint16
  end

  it "behaves as type" do
    obj = IntDelayedIO.new(3)
    obj.must_equal 3
  end

  it "does not read" do
    obj = IntDelayedIO.read "\001\002\003\004\005\006\007"
    assert obj.clear?
  end

  it "does not do_num_bytes" do
    obj = IntDelayedIO.new(3)
    obj.do_num_bytes.must_equal 0
  end

  it "does num_bytes" do
    obj = IntDelayedIO.new(3)
    obj.num_bytes.must_equal 2
  end

  it "does not write" do
    io = StringIO.new
    obj = IntDelayedIO.new(3)
    obj.write(io)
    io.value.must_equal ""
  end

  it "uses read_abs_offset" do
    obj = IntDelayedIO.new(3)
    obj.abs_offset.must_equal 5
    obj.rel_offset.must_equal 5
  end

  it "uses abs_offset if set" do
    obj = IntDelayedIO.new(3)
    obj.abs_offset = 10
    obj.abs_offset.must_equal 10
    obj.rel_offset.must_equal 10
  end

  it "must call #read before #read_now!" do
    obj = IntDelayedIO.new(3)
    lambda {
      obj.read_now!
    }.must_raise IOError
  end

  it "reads explicitly" do
    obj = IntDelayedIO.read "\001\002\003\004\005\006\007"
    obj.read_now!

    obj.must_equal 0x0607
  end

  it "must call #write before #write_now!" do
    obj = IntDelayedIO.new(3)
    lambda {
      obj.write_now!
    }.must_raise IOError
  end

  it "writes explicitly" do
    io = StringIO.new "\001\002\003\004\005\006\007\010\011"
    obj = IntDelayedIO.new(3)
    obj.write(io)
    obj.write_now!
    io.value.must_equal "\001\002\003\004\005\000\003\010\011"
  end

  it "writes explicitly after setting abs_offset" do
    io = StringIO.new "\001\002\003\004\005\006\007\010\011"
    obj = IntDelayedIO.new(7)
    obj.write(io)

    obj.abs_offset = 1
    obj.write_now!
    io.value.must_equal "\001\000\007\004\005\006\007\010\011"
  end
end

describe BinData::DelayedIO, "subclassed with multiple types" do
  class StringDelayedIO < BinData::DelayedIO
    endian :big
    default_parameter read_abs_offset: 5

    uint16 :len, value: -> { str.length }
    string :str, read_length: :len
  end

  it "behaves as type" do
    obj = StringDelayedIO.new(str: "hello")
    obj.snapshot.must_equal({len: 5, str: "hello"})
  end

  it "reads explicitly" do
    obj = StringDelayedIO.read "\001\002\003\004\005\000\003abc\013"
    obj.read_now!

    obj.snapshot.must_equal({len: 3, str: "abc"})
  end

  it "writes explicitly" do
    io = StringIO.new "\001\002\003\004\005\006\007\010\011\012\013\014\015"
    obj = StringDelayedIO.new(str: "hello")
    obj.write(io)
    obj.write_now!
    io.value.must_equal "\001\002\003\004\005\000\005hello\015"
  end
end

describe BinData::DelayedIO, "inside a Record" do
  class DelayedIORecord < BinData::Record
    endian :little

    uint16 :str_length, value: -> { str.length }
    delayed_io :str, read_abs_offset: 4 do
      string read_length: :str_length
    end
    delayed_io :my_int, read_abs_offset: 2 do
      uint16 initial_value: 7
    end
  end

  it "reads" do
    obj = DelayedIORecord.read "\x05\x00\x03\x0012345"
    obj.num_bytes.must_equal 2
    obj.snapshot.must_equal({str_length: 0, str: "", my_int: 7})
  end

  it "reads explicitly" do
    obj = DelayedIORecord.read "\x05\x00\x03\x0012345"
    obj.str.read_now!
    obj.my_int.read_now!
    obj.num_bytes.must_equal 2
    obj.snapshot.must_equal({str_length: 5, str: "12345", my_int: 3})
  end

  it "writes" do
    obj = DelayedIORecord.new(str: "abc", my_int: 2)
    io = StringIO.new
    obj.write(io)
    obj.str.write_now!
    obj.my_int.write_now!
    io.value.must_equal "\x03\x00\x02\x00abc"
  end
end

describe BinData::DelayedIO, "with auto_call" do
  class AutoCallDelayedIORecord < BinData::Record
    auto_call_delayed_io
    uint8 :a
    delayed_io :b, read_abs_offset: 1 do
      uint8
    end
  end

  it "class reads" do
    obj = AutoCallDelayedIORecord.read "\x01\x02"
    obj.snapshot.must_equal({a: 1, b: 2})
  end

  it "reads" do
    obj = AutoCallDelayedIORecord.new
    obj.read "\x01\x02"
    obj.snapshot.must_equal({a: 1, b: 2})
  end

  it "writes" do
    obj = AutoCallDelayedIORecord.new(a: 1, b: 2)
    io = StringIO.new
    obj.write(io)
    io.value.must_equal "\x01\x02"
  end

  it "to_binary_s" do
    obj = AutoCallDelayedIORecord.new(a: 1, b: 2)
    obj.to_binary_s.must_equal_binary "\x01\x02"
  end

  it "num_bytes" do
    obj = AutoCallDelayedIORecord.new(a: 1, b: 2)
    obj.num_bytes.must_equal 2
  end
end
