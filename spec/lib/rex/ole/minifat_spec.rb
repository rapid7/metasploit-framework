# -*- coding:binary -*-
require 'spec_helper'

require 'rex/ole'

describe Rex::OLE::MiniFAT do
  before(:each) do
    Rex::OLE::Util.set_endian(Rex::OLE::LITTLE_ENDIAN)
  end

  let(:storage) do
    Rex::OLE::Storage.new
  end

  subject(:minifat) do
    described_class.new(storage)
  end

  describe "#allocate_sector" do
    context "when entries is empty" do
      it "returns index 0" do
        expect(minifat.allocate_sector).to eq(0)
      end

      it "allocates idx_per_sect entries" do
        minifat.allocate_sector
        storage = minifat.instance_variable_get(:@stg)
        expect(minifat.length).to eq(storage.header.idx_per_sect)
      end

      it "marks the first entry as SECT_END" do
        minifat.allocate_sector
        expect(minifat[0]).to eq(Rex::OLE::SECT_END)
      end

      it "marks the remaining entries as SECT_FREE" do
        minifat.allocate_sector
        storage = minifat.instance_variable_get(:@stg)
        (1..storage.header.idx_per_sect - 1).each do |i|
          expect(minifat[i]).to eq(Rex::OLE::SECT_FREE)
        end
      end
    end

    context "when entries include a free sector" do
      it "returns the free sector index entry" do
        minifat + [1, 2, Rex::OLE::SECT_FREE]
        expect(minifat.allocate_sector).to eq(2)
      end
    end

    context "when entries don't include a free sector" do
      it "returns index of a new entry" do
        minifat + [1, 2, 3]
        expect(minifat.allocate_sector).to eq(3)
      end

      it "allocates idx_per_sect entries" do
        minifat + [1, 2, 3]
        minifat.allocate_sector
        storage = minifat.instance_variable_get(:@stg)
        expect(minifat.length).to eq(storage.header.idx_per_sect + 3)
      end

      it "marks the first entry as SECT_END" do
        minifat + [1, 2, 3]
        minifat.allocate_sector
        expect(minifat[3]).to eq(Rex::OLE::SECT_END)
      end

      it "marks the remaining entries as SECT_FREE" do
        minifat + [1, 2, 3]
        minifat.allocate_sector
        storage = minifat.instance_variable_get(:@stg)
        (4..3 + storage.header.idx_per_sect - 1).each do |i|
          expect(minifat[i]).to eq(Rex::OLE::SECT_FREE)
        end
      end
    end
  end

  describe "#read" do
    context "when the MiniFAT in the storage is empty" do
      it "returns zero" do
        expect(minifat.read).to eq(0)
      end
    end
  end

  describe "#write" do
    context "when entries is empty" do
      it "returns nil" do
        expect(minifat.write).to be_nil
      end
    end
  end

end
