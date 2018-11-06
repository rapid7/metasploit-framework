require 'spec_helper'


describe XDR::String, "#read" do
  subject{ XDR::String.new(3) }

  it "decodes values correctly" do
    expect(read("\x00\x00\x00\x00")).to eq("")
    expect(read("\x00\x00\x00\x01h\x00\x00\x00")).to eq("h")
    expect(read("\x00\x00\x00\x02hi\x00\x00")).to eq("hi")
  end

  it "raises a ReadError when the encoded length is greater than the allowed max" do
    expect{ read "\x00\x00\x00\x04hiya" }.to raise_error(XDR::ReadError)
  end

  def read(str)
    io = StringIO.new(str)
    subject.read(io)
  end
end

describe XDR::String, "#write" do
  subject{ XDR::String[2] }

  it "encodes values correctly" do
    expect(write("")).to eq("\x00\x00\x00\x00")
    expect(write("h")).to eq("\x00\x00\x00\x01h\x00\x00\x00")
    expect(write("hi")).to eq("\x00\x00\x00\x02hi\x00\x00")
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