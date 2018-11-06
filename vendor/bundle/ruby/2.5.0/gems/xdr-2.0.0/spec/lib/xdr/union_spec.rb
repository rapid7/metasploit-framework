require 'spec_helper'

describe XDR::Union, ".read" do
  
  subject{ UnionSpec::Result }
  let(:result){ subject.read(bytes) }

  context "with a void arm encoded" do
    let(:bytes){ StringIO.new "\x00\x00\x00\x00" }

    it "decodes correctly" do
      expect(result).to be_a(UnionSpec::Result)
      expect(result.switch).to eq(UnionSpec::ResultType.ok)
      expect(result.arm).to be_nil
      expect(result.get).to be_nil
    end
  end

  context "with a non-void arm encoded" do
    let(:bytes){ StringIO.new "\x00\x00\x00\x01\x00\x00\x00\x0812345678" }

    it "decodes correctly" do
      expect(result).to be_a(UnionSpec::Result)
      expect(result.switch).to eq(UnionSpec::ResultType.error)
      expect(result.arm).to eq(:message)
      expect(result.get).to eq("12345678")
      expect(result.message!).to eq("12345678")
    end
  end

  context "with a default arm encoded" do
    let(:bytes){ StringIO.new "\x00\x00\x00\x02" }

    it "decodes correctly" do
      expect(result).to be_a(UnionSpec::Result)
      expect(result.switch).to eq(UnionSpec::ResultType.nonsense)
      expect(result.arm).to be_nil
      expect(result.get).to be_nil
    end
  end

  context "with a switch that is not a member of the switch_type" do
    let(:bytes){ StringIO.new "\x00\x00\x00\x10" }

    it "raises EnumValueError" do
      expect{ result }.to raise_error XDR::EnumValueError
    end
  end

  context "with a invalid arm encoded" do
    let(:bytes){ StringIO.new "\x00\x00\x00\x02" }
    subject{ UnionSpec::UnforfivingResult }

    it "raises InvalidSwitchError" do
      expect{ result }.to raise_error XDR::InvalidSwitchError
    end
  end

end

describe XDR::Union, "#attribute!" do
  subject{ UnionSpec::Result.new(:ok) }

  it "raises an ArmNotSetError when the attribute requested has not been populated" do
    expect{ subject.message! }.to raise_error XDR::ArmNotSetError
  end

  it "returns the underyling value when the arm is populated" do
    subject.set(:error, "it all went bad")
    expect(subject.message!).to eq("it all went bad")
  end
end

describe XDR::Union, "#set" do
  subject{ UnionSpec::ManyTypes.new }

  it "sets the underlying member variables correctly" do
    subject.set(:fixnum, 3)
    expect(subject.switch).to eq(UnionSpec::Types.fixnum)
    expect(subject.arm).to eq(:fixnum)
    expect(subject.value).to eq(3)

    subject.set(:float, 1.0)
    expect(subject.switch).to eq(UnionSpec::Types.float)
    expect(subject.arm).to eq(:float)
    expect(subject.value).to eq(1.0)

    subject.set(:array, [1,2])
    expect(subject.switch).to eq(UnionSpec::Types.array)
    expect(subject.arm).to eq(:array)
    expect(subject.value).to eq([1,2])

    subject.set(:bool, true)
    expect(subject.switch).to eq(UnionSpec::Types.bool)
    expect(subject.arm).to eq(:bool)
    expect(subject.value).to eq(true)

    subject.set(:optional, nil)
    expect(subject.switch).to eq(UnionSpec::Types.optional)
    expect(subject.arm).to eq(:optional)
    expect(subject.value).to eq(nil)

    subject.set(:optional, 3)
    expect(subject.switch).to eq(UnionSpec::Types.optional)
    expect(subject.arm).to eq(:optional)
    expect(subject.value).to eq(3)

    subject.set(:complex, UnionSpec::Result.new(:ok))
    expect(subject.switch).to eq(UnionSpec::Types.complex)
    expect(subject.arm).to eq(:complex)
    expect(subject.value).to be_a(UnionSpec::Result)

    subject.set(:void)
    expect(subject.switch).to eq(UnionSpec::Types.void)
    expect(subject.arm).to eq(nil)
    expect(subject.value).to eq(nil)
  end

  it "raises InvalidValueError if the value provided is not compatible with the selected arm" do
    expect{ subject.set(:fixnum, 3.0)   }.to raise_error(XDR::InvalidValueError)
    expect{ subject.set(:fixnum, "hi")  }.to raise_error(XDR::InvalidValueError)
    expect{ subject.set(:fixnum, [])    }.to raise_error(XDR::InvalidValueError)
    expect{ subject.set(:fixnum, true)  }.to raise_error(XDR::InvalidValueError)

    expect{ subject.set(:float, 3)    }.to raise_error(XDR::InvalidValueError)
    expect{ subject.set(:float, "hi") }.to raise_error(XDR::InvalidValueError)
    expect{ subject.set(:float, [])   }.to raise_error(XDR::InvalidValueError)
    expect{ subject.set(:float, true) }.to raise_error(XDR::InvalidValueError)

    expect{ subject.set(:array, 3)    }.to raise_error(XDR::InvalidValueError)
    expect{ subject.set(:array, "hi") }.to raise_error(XDR::InvalidValueError)
    expect{ subject.set(:array, 3.0)  }.to raise_error(XDR::InvalidValueError)
    expect{ subject.set(:array, true) }.to raise_error(XDR::InvalidValueError)

    expect{ subject.set(:bool, 3)    }.to raise_error(XDR::InvalidValueError)
    expect{ subject.set(:bool, "hi") }.to raise_error(XDR::InvalidValueError)
    expect{ subject.set(:bool, 3.0)  }.to raise_error(XDR::InvalidValueError)
    expect{ subject.set(:bool, [])   }.to raise_error(XDR::InvalidValueError)

    expect{ subject.set(:optional, "hi") }.to raise_error(XDR::InvalidValueError)
    expect{ subject.set(:optional, 3.0)  }.to raise_error(XDR::InvalidValueError)
    expect{ subject.set(:optional, [])   }.to raise_error(XDR::InvalidValueError)
    expect{ subject.set(:optional, true) }.to raise_error(XDR::InvalidValueError)

    expect{ subject.set(:complex, 3)    }.to raise_error(XDR::InvalidValueError)
    expect{ subject.set(:complex, "hi") }.to raise_error(XDR::InvalidValueError)
    expect{ subject.set(:complex, 3.0)  }.to raise_error(XDR::InvalidValueError)
    expect{ subject.set(:complex, [])   }.to raise_error(XDR::InvalidValueError)
    expect{ subject.set(:complex, true) }.to raise_error(XDR::InvalidValueError)

    expect{ subject.set(:void, 3)    }.to raise_error(XDR::InvalidValueError)
    expect{ subject.set(:void, "hi") }.to raise_error(XDR::InvalidValueError)
    expect{ subject.set(:void, 3.0)  }.to raise_error(XDR::InvalidValueError)
    expect{ subject.set(:void, [])   }.to raise_error(XDR::InvalidValueError)
    expect{ subject.set(:void, true) }.to raise_error(XDR::InvalidValueError)
  end

  it "raises InvalidSwitchError if the provided switch is not compatible with the switch_type" do
    expect{ subject.set 4 }.to raise_error(XDR::InvalidSwitchError)
    expect{ subject.set "hi" }.to raise_error(XDR::InvalidSwitchError)
    expect{ subject.set UnionSpec::ResultType.ok }.to raise_error(XDR::InvalidSwitchError)
  end

  context "when the union does not have a default switch" do
    subject{ UnionSpec::UnforfivingResult.new }

    #TODO
  end
end

describe XDR::Union, "#switch" do
  subject{ UnionSpec::Result.new }

  it "reflects the set switch" do
    subject.set :ok
    expect( subject.switch ).to eq(UnionSpec::ResultType.ok)
    subject.set :error, "broke"
    expect( subject.switch ).to eq(UnionSpec::ResultType.error)
    subject.set :nonsense
    expect( subject.switch ).to eq(UnionSpec::ResultType.nonsense)
  end

  it "is aliased to the union's switch_name" do
    subject.set :ok
    expect( subject.type ).to eq(subject.switch)
  end
end

module UnionSpec
  class ResultType < XDR::Enum
    member :ok, 0
    member :error, 1
    member :nonsense, 2

    seal
  end

  class Types < XDR::Enum
    member :fixnum, 0
    member :float, 1
    member :array, 2
    member :bool, 3
    member :optional, 4
    member :complex, 5
    member :void, 6

    seal
  end

  class Result < XDR::Union
    switch_on ResultType, :type

    switch ResultType.ok
    switch ResultType.error, :message
    switch :default

    attribute :message, XDR::String[]
  end

  class UnforfivingResult < XDR::Union
    switch_on ResultType, :type

    switch :ok
    switch :error, :message

    attribute :message, XDR::String[]
  end

  class ManyTypes < XDR::Union
    switch_on Types, :type

    switch Types.fixnum,   :fixnum
    switch Types.float,    :float
    switch Types.array,    :array
    switch Types.bool,     :bool
    switch Types.optional, :optional
    switch Types.complex,  :complex
    switch Types.void


    attribute :fixnum,    XDR::Hyper
    attribute :float,     XDR::Double
    attribute :array,     XDR::Array[XDR::Int, 2] 
    attribute :bool,      XDR::Bool
    attribute :optional,  XDR::Option[XDR::Int]
    attribute :complex,   Result
  end
end
