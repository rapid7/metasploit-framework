#!/usr/bin/env ruby

require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

describe BinData::String, "with mutually exclusive parameters" do
  it ":value and :initial_value" do
    params = {value: "", initial_value: ""}
    lambda { BinData::String.new(params) }.must_raise ArgumentError
  end

  it ":length and :read_length" do
    params = {length: 5, read_length: 5}
    lambda { BinData::String.new(params) }.must_raise ArgumentError
  end

  it ":value and :length" do
    params = {value: "", length: 5}
    lambda { BinData::String.new(params) }.must_raise ArgumentError
  end
end

describe BinData::String, "when assigning" do
  let(:small) { BinData::String.new(length: 3, pad_byte: "A") }
  let(:large) { BinData::String.new(length: 5, pad_byte: "B") }

  it "copies data from small to large" do
    large.assign(small)
    large.must_equal "AAABB"
  end

  it "copies data from large to small" do
    small.assign(large)
    small.must_equal "BBB"
  end
end

describe BinData::String do
  let(:obj) { BinData::String.new("testing") }

  it "compares with regexp" do
    (/es/ =~ obj).must_equal 1
  end

  it "compares with regexp" do
    (obj =~ /es/).must_equal 1
  end
end

describe BinData::String, "with :read_length" do
  let(:obj) { BinData::String.new(read_length: 5) }

  specify { obj.num_bytes.must_equal 0 }
  specify { obj.value.must_equal "" }

  it "reads :read_length bytes" do
    obj.read("abcdefghij")
    obj.must_equal "abcde"
  end

  it "remembers :read_length after value is cleared" do
    obj.assign("abc")
    obj.num_bytes.must_equal 3
    obj.clear

    obj.read("abcdefghij")
    obj.must_equal "abcde"
  end
end

describe BinData::String, "with :length" do
  let(:obj) { BinData::String.new(length: 5) }

  specify { obj.num_bytes.must_equal 5 }
  specify { obj.value.must_equal "\0\0\0\0\0" }

  it "retains :length after value is set" do
    obj.assign("abcdefghij")
    obj.num_bytes.must_equal 5
  end

  it "reads :length bytes" do
    obj.read("abcdefghij")
    obj.must_equal "abcde"
  end

  it "pads values less than :length" do
    obj.assign("abc")
    obj.must_equal "abc\0\0"
  end

  it "accepts values exactly :length" do
    obj.assign("abcde")
    obj.must_equal "abcde"
  end

  it "truncates values greater than :length" do
    obj.assign("abcdefghij")
    obj.must_equal "abcde"
  end
end

describe BinData::String, "with :read_length and :initial_value" do
  let(:obj) { BinData::String.new(read_length: 5, initial_value: "abcdefghij") }

  specify { obj.num_bytes.must_equal 10 }
  specify { obj.value.must_equal "abcdefghij" }

  it "uses :read_length for reading" do
    io = StringIO.new("ABCDEFGHIJKLMNOPQRST")
    obj.read(io)
    io.pos.must_equal 5
   end

  it "forgets :initial_value after reading" do
    obj.read("ABCDEFGHIJKLMNOPQRST")
    obj.num_bytes.must_equal 5
    obj.must_equal "ABCDE"
  end
end

describe BinData::String, "with :read_length and :value" do
  let(:obj) { BinData::String.new(read_length: 5, value: "abcdefghij") }

  specify { obj.num_bytes.must_equal 10 }
  specify { obj.value.must_equal "abcdefghij" }

  it "uses :read_length for reading" do
    io = StringIO.new("ABCDEFGHIJKLMNOPQRST")
    obj.read(io)
    io.pos.must_equal 5
  end

  describe "after reading" do
    before(:each) do
      obj.read("ABCDEFGHIJKLMNOPQRST")
    end

    it "is not affected by :read_length after reading" do
      obj.num_bytes.must_equal 10
      obj.must_equal "abcdefghij"
    end

    it "returns read value while reading" do
      obj.stub :reading?, true do
        obj.must_equal "ABCDE"
      end
    end
  end
end

describe BinData::String, "with :length and :initial_value" do
  let(:obj) { BinData::String.new(length: 5, initial_value: "abcdefghij") }

  specify { obj.num_bytes.must_equal 5 }
  specify { obj.value.must_equal "abcde" }

  it "forgets :initial_value after reading" do
    io = StringIO.new("ABCDEFGHIJKLMNOPQRST")
    obj.read(io)
    io.pos.must_equal 5
    obj.num_bytes.must_equal 5
    obj.must_equal "ABCDE"
  end
end

describe BinData::String, "with :pad_byte" do
  it "accepts a numeric value for :pad_byte" do
    str = BinData::String.new(length: 5, pad_byte: 6)
    str.assign("abc")
    str.must_equal "abc\x06\x06"
  end

  it "accepts a character for :pad_byte" do
    str = BinData::String.new(length: 5, pad_byte: "R")
    str.assign("abc")
    str.must_equal "abcRR"
  end

  it "does not accept a string for :pad_byte" do
    params = {length: 5, pad_byte: "RR"}
    lambda { BinData::String.new(params) }.must_raise ArgumentError
  end
end

describe BinData::String, "with :trim_padding" do
  it "set false is the default" do
    str1 = BinData::String.new(length: 5)
    str2 = BinData::String.new(length: 5, trim_padding: false)
    str1.assign("abc")
    str2.assign("abc")
    str1.must_equal "abc\0\0"
    str2.must_equal "abc\0\0"
  end

  describe "trim padding set" do
    let(:obj) { BinData::String.new(pad_byte: 'R', trim_padding: true) }

    it "trims the value" do
      obj.assign("abcRR")
      obj.must_equal "abc"
    end

    it "does not affect num_bytes" do
      obj.assign("abcRR")
      obj.num_bytes.must_equal 5
    end

    it "trims if last char is :pad_byte" do
      obj.assign("abcRR")
      obj.must_equal "abc"
    end

    it "does not trim if value contains :pad_byte not at the end" do
      obj.assign("abcRRde")
      obj.must_equal "abcRRde"
    end
  end
end

describe BinData::String, "with :pad_front" do
  it "set false is the default" do
    str1 = BinData::String.new(length: 5)
    str2 = BinData::String.new(length: 5, pad_front: false)
    str1.assign("abc")
    str2.assign("abc")
    str1.must_equal "abc\0\0"
    str2.must_equal "abc\0\0"
  end

  it "pads to the front" do
    str = BinData::String.new(length: 5, pad_byte: 'R', pad_front: true)
    str.assign("abc")
    str.must_equal "RRabc"
  end

  it "can alternatively be accesses by :pad_left" do
    str = BinData::String.new(length: 5, pad_byte: 'R', pad_left: true)
    str.assign("abc")
    str.must_equal "RRabc"
  end

  describe "and :trim_padding" do
    let(:obj) { BinData::String.new(length: 5, pad_byte: 'R', pad_front: true, trim_padding: true) }

    it "assigns" do
      obj.assign("abc")
      obj.must_equal "abc"
    end

    it "has to_binary_s" do
      obj.assign("abc")
      obj.to_binary_s.must_equal_binary "RRabc"
    end

    it "reads" do
      obj.read "RRabc"
      obj.must_equal "abc"
    end
  end
end

describe BinData::String, "with Ruby 1.9 encodings" do
  class UTF8String < BinData::String
    def snapshot
      super.force_encoding('UTF-8')
    end
  end

  let(:obj) { UTF8String.new }
  let(:binary_str) { "\xC3\x85\xC3\x84\xC3\x96" }
  let(:utf8_str) { binary_str.dup.force_encoding('UTF-8') }

  it "stores assigned values as binary" do
    obj.assign(utf8_str)
    obj.to_binary_s.must_equal_binary binary_str
  end

  it "stores read values as binary" do
    obj = UTF8String.new(read_length: binary_str.bytesize)
    obj.read(binary_str)

    obj.to_binary_s.must_equal_binary binary_str
  end

  it "returns values in correct encoding" do
    obj.assign(utf8_str)

    obj.snapshot.must_equal utf8_str
  end

  it "has correct num_bytes" do
    obj.assign(utf8_str)

    obj.num_bytes.must_equal binary_str.bytesize
  end
end

describe BinData::String, "warnings" do
  it "warns if has :asserted_value but no :length" do
    obj = BinData::String.new(asserted_value: "ABC")
    obj.must_warn "obj does not have a :read_length parameter - returning empty string" do
      lambda { obj.read("abcde") }.must_raise BinData::ValidityError
    end
  end

  it "warns if has :value but no :read_length" do
    obj = BinData::String.new(value: "ABC")
    obj.must_warn "obj does not have a :read_length parameter - returning empty string" do
      obj.read("abcde")
    end
  end
end
