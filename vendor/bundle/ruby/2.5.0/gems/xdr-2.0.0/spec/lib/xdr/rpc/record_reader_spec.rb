require 'spec_helper'

describe XDR::RPC::RecordReader, "#read" do

  it "decodes values correctly" do
    empty_record = read "\x00\x00\x00\x00"
    last_record  = read "\x80\x00\x00\x02\x00\x00"

    expect(empty_record).to_not be_last
    expect(empty_record.length).to eq(0)
    expect(empty_record.content.string).to eq("")

    expect(last_record).to be_last
    expect(last_record.length).to eq(2)
    expect(last_record.content.string).to eq("\x00\x00")
  end

  it "raises EOFError the byte stream isn't large enough" do
    expect{ read "\x00\x00\x00\x01" }.to raise_error(EOFError)
    expect{ read "\x00\x00\x00\x08\x00\x00\x00\x01" }.to raise_error(EOFError)
  end

  def read(str)
    io = StringIO.new(str)
    subject.read(io)
  end
end