require 'spec_helper'


describe XDR::DSL::Enum, "#member" do
  subject do
    Class.new(XDR::Enum) do
      member :one, 1
      member :two, 2
    end
  end

  it "adds to the members collection of the class" do
    expect(subject.members.length).to eq(2)
    expect(subject.members[:one]).to eq(subject.one)
    expect(subject.members[:two]).to eq(subject.two)
  end

  it "raises ArgumentError if a non-integer value is used" do
    expect {
      Class.new(XDR::Enum) do
        member :one, "hi!"
      end
    }.to raise_error(ArgumentError)
  end
end

describe XDR::DSL::Enum, "#seal" do
  subject do
    Class.new(XDR::Enum) do
      member :one, 1
      member :two, 2
      seal
    end
  end

  it "marks the class as sealed" do
    expect(subject.sealed).to eq(true)
  end

  it "prevents you from adding members after being sealed" do
    expect{ subject.member :three, 3 }.to raise_error(ArgumentError)
  end

end