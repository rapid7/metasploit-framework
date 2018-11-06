require 'spec_helper'


describe XDR::DSL::Union, "#switch" do

  it "allows symbols in switch declarations" do
    expect do
      klass = Class.new(XDR::Union) do
        switch_on ResultType, :type
        switch :ok
      end

      klass.new(:ok)
    end.to_not raise_error
  end

  class ResultType < XDR::Enum
    member :ok, 0
    member :error, 1
    seal
  end
end

describe XDR::DSL::Union, "#switch_on" do
  klass = nil

  it "allows int types" do
    expect do
      klass = Class.new(XDR::Union) do
        switch_on XDR::Int, :type
        switch 0
        switch 1
      end
    end.to_not raise_error

    expect{ klass.new(0) }.to_not raise_error
    expect{ klass.new(1) }.to_not raise_error
    expect{ klass.new(2) }.to raise_error(XDR::InvalidSwitchError)
  end

  it "allows unsigned int types" do
    expect do
      klass = Class.new(XDR::Union) do
        switch_on XDR::UnsignedInt, :type
        switch 0
        switch 1
      end
    end.to_not raise_error

    expect{ klass.new(0) }.to_not raise_error
    expect{ klass.new(1) }.to_not raise_error
    expect{ klass.new(2) }.to raise_error(XDR::InvalidSwitchError)
    expect{ klass.new(-1) }.to raise_error(XDR::InvalidSwitchError)
  end

  it "allows bool types", :focus do
    klass = nil

    expect do
      klass = Class.new(XDR::Union) do
        switch_on XDR::Bool, :type
        switch true
      end
    end.to_not raise_error

    expect{ klass.new(true) }.to_not raise_error
    expect{ klass.new(false) }.to raise_error(XDR::InvalidSwitchError)
  end
end
