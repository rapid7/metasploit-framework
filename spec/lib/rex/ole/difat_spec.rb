# -*- coding:binary -*-
require 'spec_helper'

require 'rex/ole'

RSpec.describe Rex::OLE::DIFAT do
  before(:example) do
    Rex::OLE::Util.set_endian(Rex::OLE::LITTLE_ENDIAN)
  end

  let(:storage) do
    Rex::OLE::Storage.new
  end

  subject(:difat) do
    described_class.new(storage)
  end

  describe ".new" do
    it "returns a Rex::OLE::DIFAT instance" do
      expect(described_class.new(storage)).to be_a(Rex::OLE::DIFAT)
    end

    it "initializes @stg" do
      expect(difat.instance_variable_get(:@stg)).to eq(storage)
    end

    it "initializes @entries" do
      expect(difat.instance_variable_get(:@entries)).to be_an(Array)
    end

    it "initializes @entries as empty array" do
      expect(difat.instance_variable_get(:@entries)).to be_empty
    end
  end

  describe "#[]=" do
    context "when the entry doesn't exist" do
      it "sets an element in the @entries array" do
        difat[0] = 1
        expect(difat.instance_variable_get(:@entries)[0]).to eq(1)
      end
    end

    context "when the entry exists" do
      it "replaces the element in the @entries array" do
        difat[0] = 1
        difat[0] = 2
        expect(difat.instance_variable_get(:@entries)[0]).to eq(2)
      end
    end
  end

  describe "#[]" do
    context "when the entry doesn't exist" do
      it "returns nil" do
        expect(difat[3]).to eq(nil)
      end
    end

    context "when the entry exists" do
      it "returns the entry value" do
        difat[3] = 31
        expect(difat[3]).to eq(31)
      end
    end
  end


  describe "#+" do
    context "when @entries is empty" do
      it "sets the @entries values" do
        difat + [1, 2]
        expect(difat.instance_variable_get(:@entries)).to eq([1, 2])
      end
    end

    context "when @entries isn't empty" do
      it "concatenates the array to @entries" do
        difat[2] = 0
        difat + [1, 2]
        expect(difat.instance_variable_get(:@entries)).to eq([nil, nil, 0, 1, 2])
      end
    end
  end

  describe "#<<" do
    it "concatenates the element to the @entries array" do
      difat[0] = 1
      difat << 3
      expect(difat.instance_variable_get(:@entries)).to eq([1, 3])
    end
  end

  describe "#length" do
    subject(:difat_length) do
      difat.length
    end

    context "when @entries is empty" do
      it "returns 0" do
        is_expected.to eq(0)
      end
    end

    context "when @entries isn't empty" do
      it "returns the @entries length" do
        difat[0] = 1
        difat[1] = 2
        is_expected.to eq(2)
      end
    end
  end

  describe "#slice!" do
    context "when @entries is empty" do
      it "returns empty array" do
        expect(difat.slice!(0, 1)).to eq([])
      end
    end

    context "when start is out of range" do
      it "returns nil" do
        difat[0] = 1
        expect(difat.slice!(10, 1)).to eq(nil)
      end
    end

    context "when stop is 0" do
      it "returns empty array" do
        difat[0] = 1
        expect(difat.slice!(0, 0)).to eq([])
      end

      it "doesn't delete nothing" do
        difat[0] = 1
        difat.slice!(0, 0)
        expect(difat[0]).to eq(1)
      end
    end

    context "when @entries is long enough" do
      it "returns the deleted elements" do
        difat + [1, 2]
        expect(difat.slice!(0, 1)).to eq([1])
      end

      it "deletes the elements in the range" do
        difat + [1, 2]
        difat.slice!(0, 1)
        expect(difat.instance_variable_get(:@entries)).to eq([2])
      end
    end
  end

  describe "#reset" do
    it "resets the @entries array" do
      difat[0] = 1
      difat.reset
      expect(difat.length).to eq(0)
    end
  end

  describe "#each" do
    it "calls the block for every @entries element" do
      difat + [1, 2, 3]
      res = 0
      difat.each { |elem| res += elem}
      expect(res).to eq(1 + 2 + 3)
    end
  end

  describe "#to_s" do
    subject(:difat_string) do
      difat.to_s
    end

    it "returns an String" do
      is_expected.to be_an(String)
    end

    it "starts with {" do
      is_expected.to start_with('{')
    end

    it "ends with }" do
      is_expected.to end_with('}')
    end

    it "contains @entries values" do
      difat + [Rex::OLE::SECT_FAT, 1, 2, 3, Rex::OLE::SECT_DIF, Rex::OLE::SECT_FREE, Rex::OLE::SECT_END]
      is_expected.to match(/FAT, 0x1, 0x2, 0x3, DIF, FREE, END/)
    end
  end

  describe "#read" do
    context "when difat is empty" do
      it "returns nil" do
        expect(difat.read).to be_nil
      end
    end
  end

  describe "#write" do
    context "when entries is empty" do
      it "returns 0" do
        expect(difat.write).to eq(0)
      end
 
      it "fills the first 109 FAT sectors in the storage header" do
        difat.write
        storage = difat.instance_variable_get(:@stg)
        expect(storage.header._sectFat.length).to eq(109)
      end

      it "fills the first 109 FAT sectors in the storage header with SECT_FREE" do
        difat.write
        storage = difat.instance_variable_get(:@stg)
        storage.header._sectFat.each { |s|
          expect(s).to eq(Rex::OLE::SECT_FREE)
        }
      end
    end

    context "when entries length is less than 109" do
      let(:entries) { [1] * 20 }

      it "returns the number of entries" do
        difat + entries
        expect(difat.write).to eq(20)
      end

      it "fills the first 109 FAT sectors in the storage header" do
        difat + entries
        difat.write
        storage = difat.instance_variable_get(:@stg)
        expect(storage.header._sectFat.length).to eq(109)
      end

      it "fills the first FAT sectors with the entries" do
        difat + entries
        difat.write
        storage = difat.instance_variable_get(:@stg)
        (0..entries.length - 1).each { |i|
          expect(storage.header._sectFat[i]).to eq(1)
        }
      end

      it "fills the remaining FAT sectors with FREE sectors" do
        difat + entries
        difat.write
        storage = difat.instance_variable_get(:@stg)
        (entries.length..109 - 1).each { |i|
          expect(storage.header._sectFat[i]).to eq(Rex::OLE::SECT_FREE)
        }
      end
    end

    context "when entries length is 109" do
      let(:entries) { [1] * 109 }

      it "returns the number of entries" do
        difat + entries
        expect(difat.write).to eq(109)
      end

      it "fills the first 109 FAT sectors in the storage header" do
        difat + entries
        difat.write
        storage = difat.instance_variable_get(:@stg)
        expect(storage.header._sectFat.length).to eq(109)
      end

      it "fills the first 109 FAT sectors with the entries" do
        difat + entries
        difat.write
        storage = difat.instance_variable_get(:@stg)
        (0..storage.header._sectFat.length - 1).each { |i|
          expect(storage.header._sectFat[i]).to eq(1)
        }
      end
    end

    context "when entries length is greater than 109" do
      let(:entries) { [1] * 110 }

      it "raises a RuntimeError" do
        difat + entries
        expect { difat.write }.to raise_error(RuntimeError)
      end
    end

  end
end
