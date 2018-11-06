require 'spec_helper'


describe XDR::Quadruple, ".read" do
  let(:zero){ "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" }
  it "cannot decode values yet" do
    expect{ read zero }.to raise_error(NotImplementedError)
  end

  def read(str)
    io = StringIO.new(str)
    subject.read(io)
  end
end