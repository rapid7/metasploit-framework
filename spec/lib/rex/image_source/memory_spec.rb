# -*- coding:binary -*-
require 'spec_helper'

require 'rex/image_source/memory'

RSpec.describe Rex::ImageSource::Memory do

  let(:raw_data) { 'ABCDEFGHIJKLMNOP' }

  subject do
    described_class.new(raw_data)
  end

  it_should_behave_like 'Rex::ImageSource::ImageSource'

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
    context "when offset is positive" do
      let(:offset) { 1 }
      let(:len) { 10 }

      it "returns an String" do
        expect(subject.read(offset, len)).to be_a_kind_of(String)
      end

      it "returns an String of provided length" do
        expect(subject.read(offset, len).length).to eq(10)
      end

      it "returns an String with _raw_data contents starting at provided offset" do
        expect(subject.read(offset, len)).to start_with('BCD')
      end
    end

    context "when offset is negative" do
      let(:offset) { -5 }
      let(:len) { 2 }

      it "returns an String" do
        expect(subject.read(offset, len)).to be_a_kind_of(String)
      end

      it "returns an String of provided length" do
        expect(subject.read(offset, len).length).to eq(2)
      end

      it "offset is counted from the end of the _raw_data" do
        expect(subject.read(offset, len)).to eq('LM')
      end
    end

    context "when offset is out of range" do
      let(:offset) { 20 }
      let(:len) { 2 }

      it "returns nil" do
        expect(subject.read(offset, len)).to be_nil
      end
    end

    context "when len is bigger than _raw_data" do
      let(:offset) { 0 }
      let(:len) { 20 }

      it "returns an String" do
        expect(subject.read(offset, len)).to be_a_kind_of(String)
      end

      it "returns an String truncated to available contents" do
        expect(subject.read(offset, len).length).to eq(raw_data.length)
      end
    end
  end

  describe "#subsource" do
    let(:offset) { 2 }
    let(:len) { 10 }

    it "returns a new Rex::ImageSource::Memory" do
      expect(subject.subsource(offset, len)).to be_kind_of(described_class)
    end

    it "returns a new Rex::ImageSource::Memory with provided size" do
      expect(subject.subsource(offset, len).size).to eq(len)
    end

    it "returns a new Rex::ImageSource::Memory with file_offset added to the original" do
      expect(subject.subsource(offset, len).file_offset).to eq(offset + subject.file_offset)
    end

    it "returns a new Rex::ImageSource::Memory with rawdata from the original" do
      expect(subject.subsource(offset, len).rawdata).to eq(subject.rawdata[offset, len])
    end

    context "when offset is out of range" do
      let(:offset) { 20 }
      let(:len) { 2 }

      it "raises an error" do
        expect { subject.subsource(offset, len) }.to raise_error(NoMethodError)
      end
    end

    context "when len is bigger than source rawdata" do
      let(:offset) { 2 }
      let(:len) { 20 }

      it "returns a new Rex::ImageSource::Memory" do
        expect(subject.subsource(offset, len)).to be_kind_of(described_class)
      end

      it "returns a new Rex::ImageSource::Memory with provided size truncated" do
        expect(subject.subsource(offset, len).size).to eq(14)
      end

      it "returns a new Rex::ImageSource::Memory with file_offset added to the original" do
        expect(subject.subsource(offset, len).file_offset).to eq(offset + subject.file_offset)
      end

      it "returns a new Rex::ImageSource::Memory with rawdata truncated" do
        expect(subject.subsource(offset, len).rawdata).to eq('CDEFGHIJKLMNOP')
      end
    end
  end

  describe "#close" do
    it "returns nil" do
      expect(subject.close).to be_nil
    end
  end

  describe "#index" do
    let(:found) { 'FG' }
    let(:not_found) { 'XYZ' }

    context "when search available substring" do
      it "returns the index of the first occurrence" do
        expect(subject.index(found)).to eq(5)
      end

      context "when using negative offset" do
        let(:offset) { -14 }
        it "returns the index of the first occurrence" do
          expect(subject.index(found, offset)).to eq(5)
        end
      end

      context "when using positive offset" do
        let(:offset) { 1 }
        it "returns the index of the first occurrence" do
          expect(subject.index(found, offset)).to eq(5)
        end
      end
    end

    context "when search not available substring" do
      it "returns nil" do
        expect(subject.index(not_found)).to be_nil
      end
    end

    context "when using negative offset" do
      let(:offset) { -1 }
      it "start to search from offset from the end of the string" do
        expect(subject.index(found, offset)).to be_nil
      end
    end
  end

end
