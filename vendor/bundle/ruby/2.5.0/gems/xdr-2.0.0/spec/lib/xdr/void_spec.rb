require 'spec_helper'


describe XDR::Void, ".read" do

  it "decodes values correctly" do
    expect(read("\x00\x00\x00\x00")).to eq(:void)
    expect(read("\x00\x00\x00\x01")).to eq(:void)
    expect(read("\xFF\xFF\xFF\xFF")).to eq(:void)
    expect(read("\x7F\xFF\xFF\xFF")).to eq(:void)
    expect(read("\x80\x00\x00\x00")).to eq(:void)
  end

  def read(str)
    io = StringIO.new(str)
    subject.read(io)
  end
end

describe XDR::Void, ".write" do

  it "decodes values correctly" do
    expect(write :void).to eq("")
  end

  def write(val)
    io = StringIO.new()
    subject.write(val, io)
    io.string
  end
end

describe XDR::Void, ".valid?" do

  it "accepts :void" do
    expect(subject.valid?(:void)).to eq(true)
  end

  it "rejects anything not :void" do
    expect(subject.valid?(nil)).to eq(false)
    expect(subject.valid?(0)).to eq(false)
    expect(subject.valid?("hello")).to eq(false)
  end


end