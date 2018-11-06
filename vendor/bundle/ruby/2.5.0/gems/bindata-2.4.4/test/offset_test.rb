#!/usr/bin/env ruby

require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))
require 'bindata/offset'

describe BinData::Base, "offsets" do
  class ThreeByteReader < BinData::Base
    def do_read(io)
      @val = io.readbytes(3)
    end

    def snapshot
      @val
    end
  end

  class TenByteOffsetBase < BinData::Base
    def self.create(params)
      obj = self.new
      obj.initialize_child(params)
      obj
    end

    def initialize_child(params)
      @child = ThreeByteReader.new(params, self)
    end

    def snapshot
      @child.snapshot
    end

    def do_read(io)
      io.seekbytes(10)
      @child.do_read(io)
    end

    def clear
    end
  end

  let(:data) { "0123456789abcdefghijk" }
  let(:io) { StringIO.new(data) }

  describe "with :check_offset" do
    it "fails when offset is incorrect" do
      io.seek(2)
      obj = TenByteOffsetBase.create(check_offset: 10 - 4)
      lambda { obj.read(io) }.must_raise BinData::ValidityError
    end

    it "succeeds when offset is correct" do
      io.seek(3)
      obj = TenByteOffsetBase.create(check_offset: 10)
      obj.read(io).snapshot.must_equal data[3 + 10, 3]
    end

    it "fails when :check_offset fails" do
      io.seek(4)
      obj = TenByteOffsetBase.create(check_offset: -> { offset == 10 + 1 } )
      lambda { obj.read(io) }.must_raise BinData::ValidityError
    end

    it "succeeds when :check_offset succeeds" do
      io.seek(5)
      obj = TenByteOffsetBase.create(check_offset: -> { offset == 10 } )
      obj.read(io).snapshot.must_equal data[5 + 10, 3]
    end
  end

  describe "with :adjust_offset" do
    it "is mutually exclusive with :check_offset" do
      params = { check_offset: 8, adjust_offset: 8 }
      lambda { TenByteOffsetBase.create(params) }.must_raise ArgumentError
    end

    it "adjust offset when incorrect" do
      io.seek(2)
      obj = TenByteOffsetBase.create(adjust_offset: 13)
      obj.read(io).snapshot.must_equal data[2 + 13, 3]
    end

    it "succeeds when offset is correct" do
      io.seek(3)
      obj = TenByteOffsetBase.create(adjust_offset: 10)
      obj.read(io).snapshot.must_equal data[3 + 10, 3]
    end

    it "fails if cannot adjust offset" do
      io.seek(4)
      obj = TenByteOffsetBase.create(adjust_offset: -5)
      lambda { obj.read(io) }.must_raise BinData::ValidityError
    end
  end
end
