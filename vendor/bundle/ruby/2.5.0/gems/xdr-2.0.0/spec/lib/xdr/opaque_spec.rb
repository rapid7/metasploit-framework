require 'spec_helper'


describe XDR::Opaque, "#read" do
  subject{ XDR::Opaque.new(3) }

  it "decodes values correctly" do
    expect(read("\x00\x00\x00\x00")).to eq("\x00\x00\x00")
    expect(read("\x00\x01\x00\x00")).to eq("\x00\x01\x00")
  end

  def read(str)
    io = StringIO.new(str)
    subject.read(io)
  end
end

describe XDR::Opaque, "#write" do
  subject{ XDR::Opaque.new(3) }

  it "encodes values correctly" do
    expect(write("123")).to eq("123\x00")
    expect(write("124")).to eq("124\x00")
  end

  it "raises a WriteError if the value is not the correct length" do
    expect{ write("1234") }.to raise_error(XDR::WriteError)
    expect{ write("12") }.to raise_error(XDR::WriteError)
  end

  def write(val)
    io = StringIO.new()
    subject.write(val, io)
    io.string
  end
end