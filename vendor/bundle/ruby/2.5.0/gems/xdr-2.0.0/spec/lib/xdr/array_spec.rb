require 'spec_helper'

describe XDR::Array, "#read" do
  let(:empty) { XDR::Array[XDR::Int, 0] }
  let(:one)   { XDR::Array[XDR::Int, 1] }
  let(:many)  { XDR::Array[XDR::Int, 2] }

  it "decodes values correctly" do
    expect( read empty, "" ).to eq([])
    expect( read empty, "\x00\x00\x00\x00" ).to eq([])
    expect( read one, "\x00\x00\x00\x00" ).to eq([0])
    expect( read one, "\x00\x00\x00\x01" ).to eq([1])
    expect( read many, "\x00\x00\x00\x00\x00\x00\x00\x01" ).to eq([0, 1])
    expect( read many, "\x00\x00\x00\x01\x00\x00\x00\x01" ).to eq([1, 1])
  end

  it "raises EOFError the byte stream isn't large enough" do
    expect{ read many, "\x00\x00\x00\x00" }.to raise_error(EOFError)
  end

  def read(reader, str)
    io = StringIO.new(str)
    reader.read(io)
  end
end

describe XDR::Array, "#write" do
  subject{ XDR::Array[XDR::Int, 2] }

  it "encodes values correctly" do
    expect(write [1,2]).to eq("\x00\x00\x00\x01\x00\x00\x00\x02")
    expect(write [1,4]).to eq("\x00\x00\x00\x01\x00\x00\x00\x04")
  end

  it "raises a WriteError if the value is not the correct length" do
    expect{ write nil     }.to raise_error(XDR::WriteError)
    expect{ write []      }.to raise_error(XDR::WriteError)
    expect{ write [1]     }.to raise_error(XDR::WriteError)
    expect{ write [1,2,3] }.to raise_error(XDR::WriteError)
  end

  it "raises a WriteError if a child element is of the wrong type" do
    expect{ write [nil]      }.to raise_error(XDR::WriteError)
    expect{ write ["hi"]     }.to raise_error(XDR::WriteError)
    expect{ write [1,2,"hi"] }.to raise_error(XDR::WriteError)
  end

  def write(val)
    io = StringIO.new()
    subject.write(val, io)
    io.string
  end
end

describe XDR::Array, "#valid?" do
  subject{ XDR::Array[XDR::Int, 2] }

  it "rejects an empty array" do
    expect(subject.valid?([])).to be_falsey
  end

  it "accepts a filled array provided each element passes the child_type validator" do
    expect(subject.valid?([1,2])).to be_truthy
    expect(subject.valid?([2,3])).to be_truthy
  end

  it "rejects a filled array if any element is rejected by the child_type validator" do
    expect(subject.valid?(["hello", "hello"])).to be_falsey
    expect(subject.valid?([1, "hello"])).to be_falsey
    expect(subject.valid?([1, nil])).to be_falsey
    expect(subject.valid?([nil])).to be_falsey
  end
end