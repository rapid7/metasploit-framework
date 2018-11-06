require 'spec_helper'


describe XDR::UnsignedHyper, ".read" do

  it "decodes values correctly" do
    expect(read("\x00\x00\x00\x00\x00\x00\x00\x00")).to eq(0)
    expect(read("\x00\x00\x00\x00\x00\x00\x00\x01")).to eq(1)
    expect(read("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF")).to eq(2**64 - 1)
  end

  def read(str)
    io = StringIO.new(str)
    subject.read(io)
  end
end

describe XDR::UnsignedHyper, ".write" do

  it "decodes values correctly" do
    expect(write 0).to eq_bytes("\x00\x00\x00\x00\x00\x00\x00\x00")
    expect(write 1).to eq_bytes("\x00\x00\x00\x00\x00\x00\x00\x01")
    expect(write 2**64 - 1).to eq_bytes("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF")
  end

  it "raises WriteError when an Integer isn't passed" do
    expect{ write 1.0 }.to raise_error(XDR::WriteError)
    expect{ write "hi" }.to raise_error(XDR::WriteError)
  end

  def write(val)
    io = StringIO.new()
    subject.write(val, io)
    io.string
  end
end