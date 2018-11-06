require 'spec_helper'

class TestColor < XDR::Enum
  member :red, 0
  member :green, 1
  member :even_more_green, 3

  seal
end

describe XDR::Enum, ".read" do
  let(:zero) { "\x00\x00\x00\x00" }
  let(:one) { "\x00\x00\x00\x01" }
  let(:two) { "\x00\x00\x00\x02" }

  subject{ TestColor }

  it "decodes values correctly" do
    expect( read zero ).to eq(TestColor.red)
    expect( read one ).to eq(TestColor.green)
  end

  it "raises EnumValueError if the decoded value is not in the defined constants" do
    expect{ read two }.to raise_error XDR::EnumValueError
  end

  def read(str)
    io = StringIO.new(str)
    subject.read(io)
  end
end

describe XDR::Enum, ".write" do
  subject{ TestColor }

  it "encodes values correctly" do
    expect( write TestColor.red ).to   eq("\x00\x00\x00\x00")
    expect( write TestColor.green ).to eq("\x00\x00\x00\x01")
  end

  it "raises WriteError if value isn't a member" do
    expect{ write 0 }.to raise_error XDR::WriteError
    expect{ write 1 }.to raise_error XDR::WriteError
  end

  def write(val)
    io = StringIO.new()
    subject.write(val, io)
    io.string
  end
end

describe XDR::Enum, ".from_name" do
  subject{ TestColor }

  it "returns the correct value" do
    expect(subject.from_name("red")).to eq(TestColor.red)
  end

  it "allows various casings, strings or symbols" do
    expect(subject.from_name("even_more_green")).to eq(TestColor.even_more_green)
    expect(subject.from_name("EVEN_MORE_GREEN")).to eq(TestColor.even_more_green)
    expect(subject.from_name(:even_more_green)).to eq(TestColor.even_more_green)
    expect(subject.from_name(:EVEN_MORE_GREEN)).to eq(TestColor.even_more_green)
  end

  it "raises EnumNameError when the name is not a member" do
    expect{ subject.from_name("chartreuse")}.to raise_error(XDR::EnumNameError)
  end
end