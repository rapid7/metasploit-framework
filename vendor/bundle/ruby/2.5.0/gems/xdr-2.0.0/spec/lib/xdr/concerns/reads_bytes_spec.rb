require 'spec_helper'

class TestReader
  include XDR::Concerns::ReadsBytes
  public :read_bytes
end


describe XDR::Concerns::ReadsBytes, "#read_bytes"  do
  subject{ TestReader.new }

  it "raises EOFError when the requested length goes beyond the length of the stream" do
    expect{ read("", 1) }.to raise_error(EOFError)
    expect{ read("", 2) }.to raise_error(EOFError)
    expect{ read("", 10) }.to raise_error(EOFError)
    expect{ read("\x00\x01\x02", 4) }.to raise_error(EOFError)
    expect{ read("\x00\x01\x02", 10) }.to raise_error(EOFError)
  end

  it "returns the read data" do
    expect(read("", 0)).to eq("")
    expect(read("\x00", 1)).to eq("\x00")
    expect(read("\x01", 1)).to eq("\x01")
    expect(read("\x00\x01\x02", 3)).to eq("\x00\x01\x02")
  end

  def read(str, length)
    io = StringIO.new(str)
    subject.read_bytes(io, length)
  end
end