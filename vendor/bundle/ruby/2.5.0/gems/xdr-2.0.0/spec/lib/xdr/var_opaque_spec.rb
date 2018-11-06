require 'spec_helper'


describe XDR::VarOpaque, "#read" do
  subject{ XDR::VarOpaque[2] }

  it "decodes values correctly" do
    expect(read("\x00\x00\x00\x00")).to eq("")
    expect(read("\x00\x00\x00\x01\x00\x00\x00\x00")).to eq("\x00")
    expect(read("\x00\x00\x00\x01\x01\x00\x00\x00")).to eq("\x01")
    expect(read("\x00\x00\x00\x02\x00\x01\x00\x00")).to eq("\x00\x01")
  end

  it "raises a ReadError when the encoded length is greater than the allowed max" do
    expect{ read "\x00\x00\x00\x03\x00\x00\x00\x00" }.to raise_error(XDR::ReadError)
  end

  def read(str)
    io = StringIO.new(str)
    subject.read(io)
  end
end

describe XDR::VarOpaque, "#write" do
  subject{ XDR::VarOpaque[2] }

  it "encodes values correctly" do
    expect(write("")).to eq("\x00\x00\x00\x00")
    expect(write("\x00")).to eq("\x00\x00\x00\x01\x00\x00\x00\x00")
    expect(write("\x01")).to eq("\x00\x00\x00\x01\x01\x00\x00\x00")
    expect(write("\x00\x01")).to eq("\x00\x00\x00\x02\x00\x01\x00\x00")
  end

  it "raises a WriteError when the provided string is too long" do
    expect{ write "123" }.to raise_error(XDR::WriteError)
  end

  def write(val)
    io = StringIO.new()
    subject.write(val, io)
    io.string
  end
end