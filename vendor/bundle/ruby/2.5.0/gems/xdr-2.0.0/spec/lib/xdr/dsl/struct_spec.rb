require 'spec_helper'


describe XDR::DSL::Struct, "#attribute" do
  subject do
    Class.new(XDR::Struct) do
      attribute :attr1, XDR::Int
      attribute :attr2, XDR::String[]
    end
  end


  it "adds to the fields collection of the class" do
    expect(subject.fields.length).to eq(2)
    expect(subject.fields[:attr1]).to eq(XDR::Int)
    expect(subject.fields[:attr2]).to be_a(XDR::String)
  end



  it "raises ArgumentError if a non-convertible type is used" do
    expect do
      Class.new(XDR::Struct) do
        attribute :attr1, String
      end
    end.to raise_error(ArgumentError)
  end

end