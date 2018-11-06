# frozen_string_literal: true
require File.dirname(__FILE__) + '/spec_helper'

RSpec.describe YARD::CodeObjects::CodeObjectList do
  before { Registry.clear }

  describe "#push" do
    it "only allows CodeObjects::Base, String or Symbol" do
      list = CodeObjectList.new(nil)
      expect { list.push(:hash => 1) }.to raise_error(ArgumentError)
      list << "Test"
      list << :Test2
      list << ModuleObject.new(nil, :YARD)
      expect(list.size).to eq 3
    end
  end

  it "added value should be a proxy if parameter was String or Symbol" do
    list = CodeObjectList.new(nil)
    list << "Test"
    expect(list.first.class).to eq Proxy
  end

  it "contains a unique list of objects" do
    obj = ModuleObject.new(nil, :YARD)
    list = CodeObjectList.new(nil)

    list << P(:YARD)
    list << obj
    expect(list.size).to eq 1

    list << :Test
    list << "Test"
    expect(list.size).to eq 2
  end
end
