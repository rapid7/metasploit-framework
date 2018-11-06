#!/usr/bin/env ruby

require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

describe BinData::IO::Read, "reading from non seekable stream" do
  before do
    @rd, @wr = IO::pipe
    @io = BinData::IO::Read.new(@rd)
    @wr.write "a" * 2000
    @wr.write "b" * 2000
    @wr.close
  end

  after do
    @rd.close
  end

  it "has correct offset" do
    @io.readbytes(10)
    @io.offset.must_equal 10
  end

  it "seeks correctly" do
    @io.seekbytes(1999)
    @io.readbytes(5).must_equal "abbbb"
  end

  it "#num_bytes_remaining raises IOError" do
    lambda {
      @io.num_bytes_remaining
    }.must_raise IOError
  end
end

describe BinData::IO::Read, "when reading" do
  let(:stream) { StringIO.new "abcdefghij" }
  let(:io) { BinData::IO::Read.new(stream) }

  it "raises error when io is BinData::IO::Read" do
    lambda {
      BinData::IO::Read.new(BinData::IO::Read.new(""))
    }.must_raise ArgumentError
  end

  it "returns correct offset" do
    stream.seek(3, IO::SEEK_CUR)

    io.offset.must_equal 0
    io.readbytes(4).must_equal "defg"
    io.offset.must_equal 4
  end

  it "seeks correctly" do
    io.seekbytes(2)
    io.readbytes(4).must_equal "cdef"
  end

  it "reads all bytes" do
    io.read_all_bytes.must_equal "abcdefghij"
  end

  it "returns number of bytes remaining" do
    stream_length = io.num_bytes_remaining

    io.readbytes(4)
    io.num_bytes_remaining.must_equal stream_length - 4
  end

  it "raises error when reading at eof" do
    io.seekbytes(10)
    lambda {
      io.readbytes(3)
    }.must_raise EOFError
  end

  it "raises error on short reads" do
    lambda {
      io.readbytes(20)
    }.must_raise IOError
  end
end

describe BinData::IO::Read, "#with_buffer" do
  let(:stream) { StringIO.new "abcdefghijklmnopqrst" }
  let(:io) { BinData::IO::Read.new(stream) }

  it "consumes entire buffer on short reads" do
    io.with_buffer(10) do
      io.readbytes(4).must_equal "abcd"
    end
    io.offset.must_equal(10)
  end

  it "consumes entire buffer on read_all_bytes" do
    io.with_buffer(10) do
      io.read_all_bytes.must_equal "abcdefghij"
    end
    io.offset.must_equal(10)
  end

  it "restricts large reads" do
    io.with_buffer(10) do
      lambda {
        io.readbytes(15)
      }.must_raise IOError
    end
  end

  it "is nestable" do
    io.with_buffer(10) do
      io.readbytes(2).must_equal "ab"
      io.with_buffer(5) do
        io.read_all_bytes.must_equal "cdefg"
      end
      io.offset.must_equal(2 + 5)
    end
    io.offset.must_equal(10)
  end

  it "restricts large nested buffers" do
    io.with_buffer(10) do
      io.readbytes(2).must_equal "ab"
      io.with_buffer(20) do
        io.read_all_bytes.must_equal "cdefghij"
        io.offset.must_equal(10)
      end
    end
    io.offset.must_equal(10)
  end

  it "restricts large seeks" do
    io.with_buffer(10) do
      io.seekbytes(15)
    end
    io.offset.must_equal(10)
  end

  it "restricts large -ve seeks" do
    io.readbytes(2)
    io.with_buffer(10) do
      io.seekbytes(-1)
      io.offset.must_equal(2)
    end
  end

  it "greater than stream size consumes all bytes" do
    io.with_buffer(30) do
      io.readbytes(4).must_equal "abcd"
    end
    io.offset.must_equal(20)
  end

  it "restricts #num_bytes_remaining" do
    io.with_buffer(10) do
      io.readbytes(2)
      io.num_bytes_remaining.must_equal 8
    end
  end

  it "greater than stream size doesn't restrict #num_bytes_remaining" do
    io.with_buffer(30) do
      io.readbytes(2)
      io.num_bytes_remaining.must_equal 18
    end
  end
end

module IOReadWithReadahead
  def test_rolls_back_short_reads
    io.readbytes(2).must_equal "ab"
    io.with_readahead do
      io.readbytes(4).must_equal "cdef"
    end
    io.offset.must_equal 2
  end

  def test_rolls_back_read_all_bytes
    io.readbytes(3).must_equal "abc"
    io.with_readahead do
      io.read_all_bytes.must_equal "defghijklmnopqrst"
    end
    io.offset.must_equal 3
  end

  def test_inside_buffer_rolls_back_reads
    io.with_buffer(10) do
      io.with_readahead do
        io.readbytes(4).must_equal "abcd"
      end
      io.offset.must_equal 0
    end
    io.offset.must_equal 10
  end

  def test_outside_buffer_rolls_back_reads
    io.with_readahead do
      io.with_buffer(10) do
        io.readbytes(4).must_equal "abcd"
      end
      io.offset.must_equal 10
    end
    io.offset.must_equal 0
  end
end

describe BinData::IO::Read, "#with_readahead" do
  let(:stream) { StringIO.new "abcdefghijklmnopqrst" }
  let(:io) { BinData::IO::Read.new(stream) }

  include IOReadWithReadahead
end

describe BinData::IO::Read, "unseekable stream #with_readahead" do
  let(:stream) {
    io = StringIO.new "abcdefghijklmnopqrst"
    def io.pos
      raise Errno::EPIPE
    end
    io
  }
  let(:io) { BinData::IO::Read.new(stream) }

  include IOReadWithReadahead
end

describe BinData::IO::Write, "writing to non seekable stream" do
  before do
    @rd, @wr = IO::pipe
    @io = BinData::IO::Write.new(@wr)
  end

  after do
    @rd.close
    @wr.close
  end

  it "writes data" do
    @io.writebytes("1234567890")
    @rd.read(10).must_equal "1234567890"
  end

  it "has correct offset" do
    @io.writebytes("1234567890")
    @io.offset.must_equal 10
  end

  it "does not seek backwards" do
    @io.writebytes("1234567890")
    lambda {
      @io.seekbytes(-5)
    }.must_raise IOError
  end

  it "does not seek forwards" do
    lambda {
      @io.seekbytes(5)
    }.must_raise IOError
  end

  it "#num_bytes_remaining raises IOError" do
    lambda {
      @io.num_bytes_remaining
    }.must_raise IOError
  end
end

describe BinData::IO::Write, "when writing" do
  let(:stream) { StringIO.new }
  let(:io) { BinData::IO::Write.new(stream) }

  it "raises error when io is BinData::IO" do
    lambda {
      BinData::IO::Write.new(BinData::IO::Write.new(""))
    }.must_raise ArgumentError
  end

  it "writes correctly" do
    io.writebytes("abcd")

    stream.value.must_equal "abcd"
  end

  it "has #offset" do
    io.offset.must_equal 0

    io.writebytes("abcd")
    io.offset.must_equal 4

    io.writebytes("ABCD")
    io.offset.must_equal 8
  end

  it "rounds up #offset when writing bits" do
    io.writebits(123, 9, :little)
    io.offset.must_equal 2
  end

  it "flushes" do
    io.writebytes("abcd")
    io.flush

    stream.value.must_equal "abcd"
  end
end

describe BinData::IO::Write, "#with_buffer" do
  let(:stream) { StringIO.new }
  let(:io) { BinData::IO::Write.new(stream) }

  it "pads entire buffer on short reads" do
    io.with_buffer(10) do
      io.writebytes "abcde"
    end

    stream.value.must_equal "abcde\0\0\0\0\0"
  end

  it "discards excess on large writes" do
    io.with_buffer(5) do
      io.writebytes "abcdefghij"
    end

    stream.value.must_equal "abcde"
  end

  it "is nestable" do
    io.with_buffer(10) do
      io.with_buffer(5) do
        io.writebytes "abc"
      end
      io.writebytes "de"
    end

    stream.value.must_equal "abc\0\0de\0\0\0"
  end

  it "restricts large seeks" do
    io.with_buffer(10) do
      io.seekbytes(15)
    end
    io.offset.must_equal(10)
  end

  it "restricts large -ve seeks" do
    io.writebytes("12")
    io.with_buffer(10) do
      io.seekbytes(-1)
      io.offset.must_equal(2)
    end
  end
end

describe BinData::IO::Read, "reading bits in big endian" do
  let(:b1) { 0b1111_1010 }
  let(:b2) { 0b1100_1110 }
  let(:b3) { 0b0110_1010 }
  let(:io) { BinData::IO::Read.new([b1, b2, b3].pack("CCC")) }

  it "reads a bitfield less than 1 byte" do
    io.readbits(3, :big).must_equal 0b111
  end

  it "reads a bitfield more than 1 byte" do
    io.readbits(10, :big).must_equal 0b1111_1010_11
  end

  it "reads a bitfield more than 2 bytes" do
    io.readbits(17, :big).must_equal 0b1111_1010_1100_1110_0
  end

  it "reads two bitfields totalling less than 1 byte" do
    io.readbits(5, :big).must_equal 0b1111_1
    io.readbits(2, :big).must_equal 0b01
  end

  it "reads two bitfields totalling more than 1 byte" do
    io.readbits(6, :big).must_equal 0b1111_10
    io.readbits(8, :big).must_equal 0b10_1100_11
  end

  it "reads two bitfields totalling more than 2 bytes" do
    io.readbits(7, :big).must_equal 0b1111_101
    io.readbits(12, :big).must_equal 0b0_1100_1110_011
  end

  it "ignores unused bits when reading bytes" do
    io.readbits(3, :big).must_equal 0b111
    io.readbytes(1).must_equal [b2].pack("C")
    io.readbits(2, :big).must_equal 0b01
  end

  it "resets read bits to realign stream to next byte" do
    io.readbits(3, :big).must_equal 0b111
    io.reset_read_bits
    io.readbits(3, :big).must_equal 0b110
  end
end

describe BinData::IO::Read, "reading bits in little endian" do
  let(:b1) { 0b1111_1010 }
  let(:b2) { 0b1100_1110 }
  let(:b3) { 0b0110_1010 }
  let(:io) { BinData::IO::Read.new([b1, b2, b3].pack("CCC")) }

  it "reads a bitfield less than 1 byte" do
    io.readbits(3, :little).must_equal 0b010
  end

  it "reads a bitfield more than 1 byte" do
    io.readbits(10, :little).must_equal 0b10_1111_1010
  end

  it "reads a bitfield more than 2 bytes" do
    io.readbits(17, :little).must_equal 0b0_1100_1110_1111_1010
  end

  it "reads two bitfields totalling less than 1 byte" do
    io.readbits(5, :little).must_equal 0b1_1010
    io.readbits(2, :little).must_equal 0b11
  end

  it "reads two bitfields totalling more than 1 byte" do
    io.readbits(6, :little).must_equal 0b11_1010
    io.readbits(8, :little).must_equal 0b00_1110_11
  end

  it "reads two bitfields totalling more than 2 bytes" do
    io.readbits(7, :little).must_equal 0b111_1010
    io.readbits(12, :little).must_equal 0b010_1100_1110_1
  end

  it "ignores unused bits when reading bytes" do
    io.readbits(3, :little).must_equal 0b010
    io.readbytes(1).must_equal [b2].pack("C")
    io.readbits(2, :little).must_equal 0b10
  end

  it "resets read bits to realign stream to next byte" do
    io.readbits(3, :little).must_equal 0b010
    io.reset_read_bits
    io.readbits(3, :little).must_equal 0b110
  end
end

class BitWriterHelper
  def initialize
    @stringio = BinData::IO.create_string_io
    @io = BinData::IO::Write.new(@stringio)
  end

  def writebits(val, nbits, endian)
    @io.writebits(val, nbits, endian)
  end

  def writebytes(val)
    @io.writebytes(val)
  end

  def value
    @io.flushbits
    @stringio.rewind
    @stringio.read
  end
end

describe BinData::IO::Write, "writing bits in big endian" do
  let(:io) { BitWriterHelper.new }

  it "writes a bitfield less than 1 byte" do
    io.writebits(0b010, 3, :big)
    io.value.must_equal [0b0100_0000].pack("C")
  end

  it "writes a bitfield more than 1 byte" do
    io.writebits(0b10_1001_1101, 10, :big)
    io.value.must_equal [0b1010_0111, 0b0100_0000].pack("CC")
  end

  it "writes a bitfield more than 2 bytes" do
    io.writebits(0b101_1000_0010_1001_1101, 19, :big)
    io.value.must_equal [0b1011_0000, 0b0101_0011, 0b1010_0000].pack("CCC")
  end

  it "writes two bitfields totalling less than 1 byte" do
    io.writebits(0b1_1001, 5, :big)
    io.writebits(0b00, 2, :big)
    io.value.must_equal [0b1100_1000].pack("C")
  end

  it "writes two bitfields totalling more than 1 byte" do
    io.writebits(0b01_0101, 6, :big)
    io.writebits(0b001_1001, 7, :big)
    io.value.must_equal [0b0101_0100, 0b1100_1000].pack("CC")
  end

  it "writes two bitfields totalling more than 2 bytes" do
    io.writebits(0b01_0111, 6, :big)
    io.writebits(0b1_0010_1001_1001, 13, :big)
    io.value.must_equal [0b0101_1110, 0b0101_0011, 0b0010_0000].pack("CCC")
  end

  it "pads unused bits when writing bytes" do
    io.writebits(0b101, 3, :big)
    io.writebytes([0b1011_1111].pack("C"))
    io.writebits(0b01, 2, :big)

    io.value.must_equal [0b1010_0000, 0b1011_1111, 0b0100_0000].pack("CCC")
  end
end

describe BinData::IO::Write, "writing bits in little endian" do
  let(:io) { BitWriterHelper.new }

  it "writes a bitfield less than 1 byte" do
    io.writebits(0b010, 3, :little)
    io.value.must_equal [0b0000_0010].pack("C")
  end

  it "writes a bitfield more than 1 byte" do
    io.writebits(0b10_1001_1101, 10, :little)
    io.value.must_equal [0b1001_1101, 0b0000_0010].pack("CC")
  end

  it "writes a bitfield more than 2 bytes" do
    io.writebits(0b101_1000_0010_1001_1101, 19, :little)
    io.value.must_equal [0b1001_1101, 0b1000_0010, 0b0000_0101].pack("CCC")
  end

  it "writes two bitfields totalling less than 1 byte" do
    io.writebits(0b1_1001, 5, :little)
    io.writebits(0b00, 2, :little)
    io.value.must_equal [0b0001_1001].pack("C")
  end

  it "writes two bitfields totalling more than 1 byte" do
    io.writebits(0b01_0101, 6, :little)
    io.writebits(0b001_1001, 7, :little)
    io.value.must_equal [0b0101_0101, 0b0000_0110].pack("CC")
  end

  it "writes two bitfields totalling more than 2 bytes" do
    io.writebits(0b01_0111, 6, :little)
    io.writebits(0b1_0010_1001_1001, 13, :little)
    io.value.must_equal [0b0101_0111, 0b1010_0110, 0b0000_0100].pack("CCC")
  end

  it "pads unused bits when writing bytes" do
    io.writebits(0b101, 3, :little)
    io.writebytes([0b1011_1111].pack("C"))
    io.writebits(0b01, 2, :little)

    io.value.must_equal [0b0000_0101, 0b1011_1111, 0b0000_0001].pack("CCC")
  end
end

describe BinData::IO::Read, "with changing endian" do
  it "does not mix different endianess when reading" do
    b1 = 0b0110_1010
    b2 = 0b1110_0010
    str = [b1, b2].pack("CC")
    io = BinData::IO::Read.new(str)

    io.readbits(3, :big).must_equal 0b011
    io.readbits(4, :little).must_equal 0b0010
  end
end

describe BinData::IO::Write, "with changing endian" do
  it "does not mix different endianess when writing" do
    io = BitWriterHelper.new
    io.writebits(0b110, 3, :big)
    io.writebits(0b010, 3, :little)
    io.value.must_equal [0b1100_0000, 0b0000_0010].pack("CC")
  end
end
