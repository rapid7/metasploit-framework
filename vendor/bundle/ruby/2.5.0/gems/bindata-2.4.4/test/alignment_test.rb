#!/usr/bin/env ruby

require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

describe BinData::ResumeByteAlignment do
  class ResumeAlignmentRecord < BinData::Record
    bit4 :a
    resume_byte_alignment
    bit4 :b
  end

  let(:obj) { ResumeAlignmentRecord.new }

  it "resets read alignment" do
    obj.read "\x12\x34"

    obj.a.must_equal 1
    obj.b.must_equal 3
  end

  it "resets write alignment" do
    obj.assign(a: 2, b: 7)

    obj.to_binary_s.must_equal_binary "\x20\x70"
  end
end

describe BinData::BitAligned do
  it "does not apply to BinData::Primitives" do
    lambda {
      class BitAlignedPrimitive < BinData::Primitive
        bit_aligned
      end
    }.must_raise RuntimeError
  end

  class BitString < BinData::String
    bit_aligned
  end

  class BitAlignedRecord < BinData::Record
    bit4 :preamble
    bit_string :str, length: 2
    bit4 :afterward
  end

  let(:obj) { BitAlignedRecord.new }

  it "#num_bytes as expected" do
    obj.num_bytes.must_equal 3
  end

  it "has expected abs_offset" do
    obj.str.abs_offset.must_equal 0
  end

  it "reads as expected" do
    obj.read("\x56\x36\x42")
    obj.snapshot.must_equal({preamble: 5, str: "cd", afterward: 2})
  end

  it "writes as expected" do
    obj.assign(preamble: 5, str: "ab", afterward: 1)
    obj.to_binary_s.must_equal_binary "\x56\x16\x21"
  end
end
