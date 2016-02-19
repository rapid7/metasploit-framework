# -*- coding:binary -*-
require 'spec_helper'

require 'rex/image_source/disk'

RSpec.describe Rex::ImageSource::Disk do

  let(:path) do
    File.join(Msf::Config.data_directory, "templates", "template_x86_windows_old.exe")
  end

  let(:file) do
    File.new(path)
  end

  subject do
    described_class.new(file)
  end

  it_should_behave_like 'Rex::ImageSource::ImageSource'

  describe "#initialize" do
    subject(:disk_class) do
      described_class.allocate
    end

    context "when _len not sent as argument" do
      let(:_file) { file }

      it "initializes size to file length" do
        disk_class.send(:initialize, file)
        expect(disk_class.size).to eq(4608)
      end
    end

    context "when _offset not sent as argument" do
      let(:_file) { file }
      it "initializes file_offset to 0" do
        disk_class.send(:initialize, file)
        expect(disk_class.file_offset).to eq(0)
      end
    end
  end

  describe "#read" do
    context "when offset less than 0" do
      let(:offset) { -1 }
      let(:len) { 20 }

      it "raises a RangeError" do
        expect { subject.read(offset, len) }.to raise_error(RangeError)
      end
    end

    context "offset plus len greater than size" do
      let(:offset) { 0 }
      let(:len) { 16000 }

      it "raises a RangeError" do
        expect { subject.read(offset, len) }.to raise_error(RangeError)
      end
    end

    context "when offset and len inside range" do
      let(:offset) { 0 }
      let(:len) { 2 }

      it "returns file contents" do
        expect(subject.read(offset, len)). to eq('MZ')
      end
    end

    context "instance with tampered size" do
      let(:tampered_size) { 6000 }

      subject(:tampered) do
        described_class.new(file, 0, tampered_size)
      end

      context "when reading offset after the real file length" do
        let(:offset) { 5000 }
        let(:len) { 2 }
        it "returns nil" do
          expect(tampered.read(offset, len)).to be_nil
        end
      end
    end
  end

  describe "#index" do
    let(:search) { 'MZ' }

    it "returns index of first search occurrence" do
      expect(subject.index(search)).to eq(0)
    end

    context "when offset out of range" do
      it "returns nil" do
        expect(subject.index(search, 6000)).to be_nil
      end
    end

    context "when search string not found" do
      it "returns nil" do
        expect(subject.index(search, 4600)).to be_nil
      end
    end

    context "instance with tampered size" do
      let(:tampered_size) { 6000 }

      subject(:tampered) do
        described_class.new(file, 0, tampered_size)
      end

      context "when searching offset after the real file length" do
        let(:offset) { 5000 }
        it "raises NoMethodError" do
          expect{ tampered.index(search, offset) }.to raise_error(NoMethodError)
        end
      end
    end
  end

  describe "#subsource" do
    let(:offset) { 2 }
    let(:len) { 512 }

    it "returns a new Rex::ImageSource::Disk" do
      expect(subject.subsource(offset, len)).to be_kind_of(described_class)
    end

    it "returns a new Rex::ImageSource::Disk with same file" do
      expect(subject.subsource(offset, len).file).to eq(subject.file)
    end

    it "returns a new Rex::ImageSource::Disk with provided size" do
      expect(subject.subsource(offset, len).size).to eq(len)
    end

    it "returns a new Rex::ImageSource::Disk with file_offset added to the original" do
      expect(subject.subsource(offset, len).file_offset).to eq(offset + subject.file_offset)
    end
  end

  describe "#close" do
    it "returns nil" do
      expect(subject.close).to be_nil
    end

    it "closes the associated file" do
      expect(subject.file.closed?).to be_falsey
      subject.close
      expect(subject.file.closed?).to be_truthy
    end
  end
end
