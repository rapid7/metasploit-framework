require 'spec_helper'

module StructSpec
  class SampleError < XDR::Struct
    attribute :code, XDR::Int
    attribute :msg,  XDR::String[100]
  end


  # class SampleEnvelope < XDR::Struct
  #   attribute :body,  XDR::VarOpaque[]
  #   attribute :sigs,  XDR::VarArray[XDR::Opaque[32]]
  # end

  # class SampleOptions < XDR::Struct
  #   attribute :limit,       XDR::Option[XDR::Int]
  #   attribute :subscribed,  XDR::Option[XDR::Bool]
  # end
end


describe XDR::Struct, "creation" do
  let(:args){ {} }
  subject{ StructSpec::SampleError.new(args) }

  context "with no args" do
    it "creates an instance" do
      expect(subject).to be_a(StructSpec::SampleError)
    end
  end

  context "with valid args" do
    let(:args){{code: 3, msg: "It broke!"}}

    it "assigns values correctly" do
      expect(subject.code).to eq(3)
      expect(subject.msg).to eq("It broke!")
    end
  end
end

describe XDR::Struct, "attribute assignment" do
  subject{ StructSpec::SampleError.new }

  it "roundtrips correctly" do
    expect(subject.code).to be_nil
    expect(subject.msg).to be_nil

    subject.code = 10
    subject.msg = "busted"

    expect(subject.code).to eq(10)
    expect(subject.msg).to eq("busted")
  end
end


describe XDR::Struct, "valid?"
describe XDR::Struct, "optional members"

describe XDR::Struct, "#to_xdr" do
  subject{ StructSpec::SampleError.new({code: 3, msg: "It broke!"}) }
  let(:result){ subject.to_xdr }

  it "serialized each field in order" do
    expect(result[0...4]).to eq("\x00\x00\x00\x03")
    expect(result[4...8]).to eq([9].pack("l>"))
    expect(result[8..-1]).to eq("It broke!\x00\x00\x00")
  end

  it "raises an exception if the struct is not valid" do
    subject.code = nil
    expect{ result }.to raise_error(XDR::WriteError)
  end

  it "produces hex" do
    result = subject.to_xdr(:hex)
    expect(result).to eq("000000030000000949742062726f6b6521000000")
  end

  it "produces base64" do
    result = subject.to_xdr(:base64)
    expect(result).to eq("AAAAAwAAAAlJdCBicm9rZSEAAAA=")
  end
end


describe XDR::Struct, ".read" do
  subject{ StructSpec::SampleError }
  let(:result){ read "\x00\x00\x00\x01\x00\x00\x00\x0812345678" }
  it "decodes values correctly" do
    expect( result ).to be_a(subject)
    expect( result.code  ).to eq(1)
    expect( result.msg  ).to eq("12345678")
  end

  def read(str)
    io = StringIO.new(str)
    subject.read(io)
  end
end