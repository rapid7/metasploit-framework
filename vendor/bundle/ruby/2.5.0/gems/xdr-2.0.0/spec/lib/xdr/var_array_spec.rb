require 'spec_helper'

describe XDR::VarArray, "#read" do
  let(:empty_array) { "\x00\x00\x00\x00" }
  let(:one_array) { "\x00\x00\x00\x01\x00\x00\x00\x00" }
  let(:many_array) { "\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x00" }
  let(:too_large_array) { "\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x02" }

  subject{ XDR::VarArray[XDR::Int, 2] }

  it "decodes values correctly" do
    expect(read(empty_array)).to eq([])
    expect(read(one_array)).to eq([0])
    expect(read(many_array)).to eq([3,0])
  end

  it "raises ReadError when the encoded array is too large" do
    expect{ read(too_large_array) }.to raise_error(XDR::ReadError)
  end

  def read(str)
    io = StringIO.new(str)
    subject.read(io)
  end
end


describe XDR::VarArray, "#write" do
  subject{ XDR::VarArray[XDR::Int, 3] }

  it "encodes values correctly" do
    expect(write([])).to eq("\x00\x00\x00\x00")
    expect(write([7])).to eq("\x00\x00\x00\x01\x00\x00\x00\x07")
    expect(write([1,2,3])).to eq("\x00\x00\x00\x03\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03")
  end

  it "raises WriteError when the array to encode is too large" do
    expect{ write([0,1,2,3]) }.to raise_error(XDR::WriteError)
  end

  def write(val)
    io = StringIO.new
    subject.write(val,io)
    io.string
  end
end

describe XDR::VarArray, "#valid?" do
  subject{ XDR::VarArray[XDR::Int, 3] }

  it "accepts an empty array" do
    expect(subject.valid?([])).to be_truthy
  end

  it "accepts a filled array provided each element passes the child_type validator" do
    expect(subject.valid?([1])).to be_truthy
    expect(subject.valid?([1,2])).to be_truthy
  end

  it "rejects a filled array if any element is rejected by the child_type validator" do
    expect(subject.valid?(["hello"])).to be_falsey
    expect(subject.valid?([1, "hello"])).to be_falsey
    expect(subject.valid?([1, "hello", 1])).to be_falsey
    expect(subject.valid?([1, nil])).to be_falsey
    expect(subject.valid?([nil])).to be_falsey
  end

  it "rejects arrays that are too large" do
    expect(subject.valid?([1,2,3,4])).to be_falsey
  end
end