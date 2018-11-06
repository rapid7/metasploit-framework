require 'spec_helper'

describe XDR::Bool, ".read" do
  subject{ XDR::Bool }

  let(:false_s) {  "\x00\x00\x00\x00" }
  let(:true_s)  {  "\x00\x00\x00\x01" }
  let(:two)     {  "\x00\x00\x00\x02" }

  it "decodes values correctly" do
    expect(read(false_s)).to eq(false)
    expect(read(true_s)).to eq(true)
  end

  it "raises ReadError if the decoded value is not 0 or 1" do
    expect{ read two }.to raise_error XDR::ReadError
  end

  def read(str)
    io = StringIO.new(str)
    subject.read(io)
  end
end

describe XDR::Bool, ".write" do
  subject{ XDR::Bool }

  it "encodes values correctly" do
    expect(write false).to eq("\x00\x00\x00\x00")
    expect(write true).to eq("\x00\x00\x00\x01")
  end

  it "raises WriteError if the value is boolean" do
    expect{ write 1 }.to raise_error XDR::WriteError
    expect{ write "hello" }.to raise_error XDR::WriteError
  end

  def write(val)
    io = StringIO.new()
    subject.write(val, io)
    io.string
  end
end