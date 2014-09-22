# -*- coding:binary -*-
require 'spec_helper'

require 'rex/image_source/memory'

describe Rex::ImageSource::Memory do

  let(:raw_data) { 'ABCDEFGHIJKLMNOP' }

  subject do
    described_class.new(raw_data)
  end

  describe "#initialize" do
    subject(:memory_class) do
      described_class.allocate
    end

    it "initializes size to data length" do
      memory_class.send(:initialize, raw_data)
      expect(memory_class.size).to eq(raw_data.length)
    end

    it "initializes file_offset to 0 by default" do
      memory_class.send(:initialize, raw_data)
      expect(memory_class.file_offset).to eq(0)
    end

    context "when using nil as data" do
      it "raises an error" do
        expect { memory_class.send(:initialize, nil) }.to raise_error(NoMethodError)
      end
    end
  end

  describe "#read" do
    context "when offset and len inside range" do
      let(:offset) { 1 }
      let(:len) { 10 }

      it "returns an String" do
        expect(subject.read(offset, len)).to be_a_kind_of(String)
      end

      it "returns an String of provided length" do
        expect(subject.read(offset, len).length).to eq(10)
      end

      it "returns an String with contents starting at provided offset" do
        expect(subject.read(offset, len)).to start_with('BCD')
      end
    end
  end

  describe "#subsource" do

  end

  describe "#close" do

  end

  describe "#index" do

  end

end
