require 'spec_helper'

describe XDR::Concerns::ConvertsToXDR do
  subject{ UnimplementedConvertible.new }

  it "requires an implementation of #read" do
    expect{ subject.read(StringIO.new) }.to raise_error(NotImplementedError)
  end

  it "requires an implementation of #write" do
    expect{ subject.write(3, StringIO.new) }.to raise_error(NotImplementedError)
  end

  it "requires an implementation of #valid?" do
    expect{ subject.valid?(3) }.to raise_error(NotImplementedError)
  end
end

describe XDR::Concerns::ConvertsToXDR, "#to_xdr" do
  subject{ ImplementedConvertible.new }

  it "calls through to write" do
    expect(subject).to receive(:write).with("hiya", kind_of(StringIO))
    subject.to_xdr("hiya")
  end

  context "using an actual xdr type" do
    subject{ XDR::Opaque.new(4) }

    it "encodes to hex" do
      r = subject.to_xdr("\x00\x01\x02\x03", "hex")
      expect(r).to eql("00010203")
    end

    it "encodes to base64" do
      r = subject.to_xdr("\x00\x01\x02\x03", "base64")
      expect(r).to eql("AAECAw==")
    end
  end
end

describe XDR::Concerns::ConvertsToXDR, "#from_xdr" do
  subject{ ImplementedConvertible.new }

  it "calls through to read" do
    allow(subject).to receive(:read).and_call_original
    subject.from_xdr("hiya")
    expect(subject).to have_received(:read).with(kind_of(StringIO))
  end

  context "using an actual xdr type" do
    subject{ XDR::Opaque.new(4) }

    it "decodes from hex" do
      r = subject.from_xdr("00010203", "hex")
      expect(r).to eql("\x00\x01\x02\x03")
    end

    it "decodes from base64" do
      r = subject.from_xdr("AAECAw==", "base64")
      expect(r).to eql("\x00\x01\x02\x03")
    end

    it "raises an ArgumentError if the input is not fully consumed" do
      expect{ subject.from_xdr("\x00\x00\x00\x00\x00") }.to raise_error(ArgumentError)
    end
  end
end

class UnimplementedConvertible
  include XDR::Concerns::ConvertsToXDR
end

class ImplementedConvertible
  include XDR::Concerns::ConvertsToXDR

  def read(io)
    read_bytes(io, 4)
  end

  def write(val, io)
    io.write(val)
  end

  def valid?(val)
    true
  end
end
