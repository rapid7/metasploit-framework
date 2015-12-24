# -*- coding:binary -*-
require 'spec_helper'

require 'rex/ole'

RSpec.describe Rex::OLE::DirEntry do
  before(:each) do
    Rex::OLE::Util.set_endian(Rex::OLE::LITTLE_ENDIAN)
  end

  let(:storage) do
    Rex::OLE::Storage.new
  end

  subject(:dir_entry) do
    described_class.new(storage)
  end

  describe ".new" do
    it "returns a Rex::OLE::DirEntry instance" do
      expect(described_class.new(storage)).to be_a(Rex::OLE::DirEntry)
    end

    it { expect(dir_entry.instance_variable_get(:@stg)).to eq(storage) }
    it { expect(dir_entry.sid).to eq(0) }
    it { expect(dir_entry.instance_variable_get(:@_ab)).to eq('Root Entry') }
    it { expect(dir_entry.instance_variable_get(:@_cb)).to be_nil }
    it { expect(dir_entry.instance_variable_get(:@_mse)).to eq(Rex::OLE::STGTY_ROOT) }
    it { expect(dir_entry.instance_variable_get(:@_bflags)).to eq(0) }
    it { expect(dir_entry._sidLeftSib).to eq(Rex::OLE::SECT_FREE) }
    it { expect(dir_entry._sidRightSib).to eq(Rex::OLE::SECT_FREE) }
    it { expect(dir_entry._sidChild).to eq(Rex::OLE::SECT_FREE) }
    it { expect(dir_entry.instance_variable_get(:@_clsId)).to be_a(Rex::OLE::CLSID) }
    it { expect(dir_entry.instance_variable_get(:@_dwUserFlags)).to eq(0) }
    it { expect(dir_entry.instance_variable_get(:@_ctime)).to eq("\x00" * 8) }
    it { expect(dir_entry.instance_variable_get(:@_mtime)).to eq("\x00" * 8) }
    it { expect(dir_entry.instance_variable_get(:@_sectStart)).to eq(Rex::OLE::SECT_END) }
    it { expect(dir_entry.instance_variable_get(:@_ulSize)).to eq(0) }
    it { expect(dir_entry.instance_variable_get(:@children)).to be_an(Array) }
    it { expect(dir_entry.instance_variable_get(:@children)).to be_empty }
  end

  describe "#length" do
    it "returns _ulSize" do
      dir_entry.instance_variable_set(:@_ulSize, 28)
      expect(dir_entry.length).to eq(28)
    end
  end

  describe "#<<" do
    it "increments the children array" do
      dir_entry << 1
      children = dir_entry.instance_variable_get(:@children)
      expect(children.length).to eq(1)
    end

    it "appends to the children array" do
      dir_entry << 1
      children = dir_entry.instance_variable_get(:@children)
      expect(children).to eq([1])
    end
  end

  describe "#each" do
    it "calls the block for every children element" do
      dir_entry << 1
      dir_entry << 2
      dir_entry << 3
      res = 0
      dir_entry.each { |elem| res += elem}
      expect(res).to eq(1 + 2 + 3)
    end
  end

  describe "#type" do
    it "returns the _mse field" do
      expect(dir_entry.type).to eq(Rex::OLE::STGTY_ROOT)
    end
  end

  describe "#type=" do
    it "modifies the _mse field" do
      dir_entry.type = 3838
      expect(dir_entry.instance_variable_get(:@_mse)).to eq(3838)
    end
  end

  describe "#name" do
    it "returns the _ab field" do
      expect(dir_entry.name).to eq('Root Entry')
    end
  end

  describe "#name=" do
    it "modifies the _ab field" do
      dir_entry.name = 'test'
      expect(dir_entry.instance_variable_get(:@_ab)).to eq('test')
    end
  end

  describe "#start_sector" do
    it "returns the _sectStart field" do
      expect(dir_entry.start_sector).to eq(Rex::OLE::SECT_END)
    end
  end

  describe "#start_sector=" do
    it "modifies the _sectStart field" do
      dir_entry.start_sector = Rex::OLE::SECT_FREE
      expect(dir_entry.instance_variable_get(:@_sectStart)).to eq(Rex::OLE::SECT_FREE)
    end
  end

  describe "#find_stream_by_name_and_type" do
    context "when any children matches the search criteria" do
      it "returns nil" do
        expect(dir_entry.find_stream_by_name_and_type('name', Rex::OLE::STGTY_ROOT)).to be_nil
      end
    end

    context "when one children matches the search criteria" do
      let(:stream) { Rex::OLE::Stream.new(storage) }
      let(:name) { 'name' }
      let(:type) { Rex::OLE::STGTY_ROOT }
      it "returns the matching stream" do
        stream.name = name
        stream.type = type
        dir_entry << stream
        expect(dir_entry.find_stream_by_name_and_type(name, type)).to eq(stream)
      end
    end

    context "when several children matches the search criteria" do
      let(:stream) { Rex::OLE::Stream.new(storage) }
      let(:stream_two) { Rex::OLE::Stream.new(storage) }
      let(:name) { 'name' }
      let(:type) { Rex::OLE::STGTY_ROOT }
      let(:sid)  { 2 }
      it "returns the first matching stream" do
        stream.name = name
        stream.type = type
        dir_entry << stream

        stream_two.name = name
        stream_two.type = type
        stream_two.sid = sid
        dir_entry << stream_two
        expect(dir_entry.find_stream_by_name_and_type(name, type)).to eq(stream)
      end
    end
  end

  describe "#find_by_sid" do
    let(:stream) { Rex::OLE::Stream.new(storage) }
    let(:another_stream) { Rex::OLE::Stream.new(storage) }

    context "when self match the criteria" do
      it "returns self" do
        expect(dir_entry.find_by_sid(0, dir_entry)).to eq(dir_entry)
      end
    end

    context "when self and a children stream match the criteria" do
      it "returns self" do
        stream.sid = 0
        dir_entry << stream
        expect(dir_entry.find_by_sid(0, dir_entry)).to eq(dir_entry)
      end
    end

    context "when only one children stream match the criteria" do
      it "returns the child stream" do
        stream.sid = 20
        dir_entry << stream
        expect(dir_entry.find_by_sid(20, dir_entry)).to eq(stream)
      end
    end

    context "when several children stream match the criteria" do
      it "returns the first child" do
        stream.sid = 20
        stream.name = 'stream'
        dir_entry << stream
        another_stream.sid = 20
        another_stream.name = 'another'
        dir_entry << another_stream
        expect(dir_entry.find_by_sid(20, dir_entry)).to eq(stream)
      end
    end
  end

  describe "#from_s" do
    let(:valid_direntry) do
      "\x52\x00\x6f\x00\x6f\x00\x74\x00\x20\x00\x45\x00\x6e\x00\x74\x00\x72\x00\x79\x00\x00\x00" + # name (_ab)
      ("\x00" * 42) + # padding
      "\x16\x00" + # _cb
      "\x05" + # _mse
      "\x00" + #_bflags
      "\xff\xff\xff\xff" + # _sidLeftSib
      "\xff\xff\xff\xff" + # _sidRightSib
      "\xff\xff\xff\xff" + # _sidChild
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + # clsid
      "\x00\x00\x00\x00" + # _dwUserFlags
      "\x00\x00\x00\x00\x00\x00\x00\x00" + # _ctime
      "\x00\x00\x00\x00\x00\x00\x00\x00" + # _metime
      "\xfe\xff\xff\xff" + # _sectStart
      "\x00\x00\x00\x00\x00\x00\x00\x00" # _ulSize
    end

    let(:invalid_name_length)do
      "\x52\x00\x6f\x00\x6f\x00\x74\x00\x20\x00\x45\x00\x6e\x00\x74\x00\x72\x00\x79\x00\x00\x00" + # name (_ab)
      ("\x00" * 42) + # padding
      "\x41\x00" + # _cb (invalid, major than 0x40)
      "\x05" + # _mse
      "\x00" + #_bflags
      "\xff\xff\xff\xff" + # _sidLeftSib
      "\xff\xff\xff\xff" + # _sidRightSib
      "\xff\xff\xff\xff" + # _sidChild
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + # clsid
      "\x00\x00\x00\x00" + # _dwUserFlags
      "\x00\x00\x00\x00\x00\x00\x00\x00" + # _ctime
      "\x00\x00\x00\x00\x00\x00\x00\x00" + # _metime
      "\xfe\xff\xff\xff" + # _sectStart
      "\x00\x00\x00\x00\x00\x00\x00\x00" # _ulSize
    end

    let(:mismatch_length) do
      "\x52\x00\x6f\x00\x6f\x00\x74\x00\x20\x00\x45\x00\x6e\x00\x74\x00\x72\x00\x79\x00\x00\x00" + # name (_ab)
      ("\x00" * 42) + # padding
      "\x13\x00" + # _cb (invalid length, shorter than real name length)
      "\x05" + # _mse
      "\x00" + #_bflags
      "\xff\xff\xff\xff" + # _sidLeftSib
      "\xff\xff\xff\xff" + # _sidRightSib
      "\xff\xff\xff\xff" + # _sidChild
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + # clsid
      "\x00\x00\x00\x00" + # _dwUserFlags
      "\x00\x00\x00\x00\x00\x00\x00\x00" + # _ctime
      "\x00\x00\x00\x00\x00\x00\x00\x00" + # _metime
      "\xfe\xff\xff\xff" + # _sectStart
      "\x00\x00\x00\x00\x00\x00\x00\x00" # _ulSize
    end

    let(:sid) { 0 }

    context "when name length major than 64" do
      it "raises RuntimeError" do
        expect { dir_entry.from_s(sid, invalid_name_length) }.to raise_error(RuntimeError)
      end
    end

    context "when name length doesn't match real length" do
      it "raises RuntimeError" do
        expect { dir_entry.from_s(sid, mismatch_length) }.to raise_error(RuntimeError)
      end
    end

    context "when valid buf" do
      it "uses argument sid" do
        dir_entry.from_s(sid, valid_direntry)
        expect(dir_entry.sid).to eq(sid)
      end

      it "parses _ab from buf" do
        dir_entry.from_s(sid, valid_direntry)
        expect(dir_entry.instance_variable_get(:@_ab)).to eq('Root Entry')
      end

      it "parses _cb from buf" do
        dir_entry.from_s(sid, valid_direntry)
        expect(dir_entry.instance_variable_get(:@_cb)).to eq(22)
      end

      it "parses _mse from buf" do
        dir_entry.from_s(sid, valid_direntry)
        expect(dir_entry.instance_variable_get(:@_mse)).to eq(Rex::OLE::STGTY_ROOT)
      end

      it "parses _bflags from buf" do
        dir_entry.from_s(sid, valid_direntry)
        expect(dir_entry.instance_variable_get(:@_bflags)).to eq(0)
      end

      it "parses _sidLeftSib from buf" do
        dir_entry.from_s(sid, valid_direntry)
        expect(dir_entry._sidLeftSib).to eq(Rex::OLE::SECT_FREE)
      end

      it "parses _sidRightSib from buf" do
        dir_entry.from_s(sid, valid_direntry)
        expect(dir_entry._sidRightSib).to eq(Rex::OLE::SECT_FREE)
      end

      it "parses _sidChild from buf" do
        dir_entry.from_s(sid, valid_direntry)
        expect(dir_entry._sidChild).to eq(Rex::OLE::SECT_FREE)
      end

      it "parses _clsId from buf" do
        dir_entry.from_s(sid, valid_direntry)
        expect(dir_entry.instance_variable_get(:@_clsId)).to be_a(Rex::OLE::CLSID)
      end

      it "parses _dwUserFlags from buf" do
        dir_entry.from_s(sid, valid_direntry)
        expect(dir_entry.instance_variable_get(:@_dwUserFlags)).to eq(0)
      end

      it "parses _ctime from buf" do
        dir_entry.from_s(sid, valid_direntry)
        expect(dir_entry.instance_variable_get(:@_ctime)).to eq("\x00" * 8)
      end

      it "parses _mtime from buf" do
        dir_entry.from_s(sid, valid_direntry)
        expect(dir_entry.instance_variable_get(:@_mtime)).to eq("\x00" * 8)
      end

      it "parses _sectStart from buf" do
        dir_entry.from_s(sid, valid_direntry)
        expect(dir_entry.instance_variable_get(:@_sectStart)).to eq(Rex::OLE::SECT_END)
      end

      it "parses _ulSize from buf" do
        dir_entry.from_s(sid, valid_direntry)
        expect(dir_entry.instance_variable_get(:@_ulSize)).to eq(0)
      end
    end
  end

  describe "#pack" do
    it "returns an string" do
      expect(dir_entry.pack).to be_an(String)
    end

    it "includes the unicode dir entry name" do
      expect(dir_entry.pack).to match(/R\x00o\x00o\x00t\x00 \x00E\x00n\x00t\x00r\x00y\x00/)
    end

    context "when _sectStart is undefined" do
      it "sets _sectStart to SECT_END" do
        dir_entry.instance_variable_set(:@_sectStart, nil)
        dir_entry.pack
        expect(dir_entry.instance_variable_get(:@_sectStart)).to eq(Rex::OLE::SECT_END)
      end
    end

    context "when _sectStart is defined" do
      it "doesn't modify _sectStart value" do
        dir_entry.instance_variable_set(:@_sectStart, Rex::OLE::SECT_FREE)
        dir_entry.pack
        expect(dir_entry.instance_variable_get(:@_sectStart)).to eq(Rex::OLE::SECT_FREE)
      end
    end

    it "sets _cb as the unicode length of the name" do
      dir_entry.pack
      expect(dir_entry.instance_variable_get(:@_cb)).to eq("Root Entry\x00".length * 2)
    end
  end

  describe "#to_s" do
    it "returns an string" do
      expect(dir_entry.to_s).to be_an(String)
    end

    it "starts with {" do
      expect(dir_entry.to_s).to start_with('{')
    end

    it "ends with }" do
      expect(dir_entry.to_s).to end_with('}')
    end

    it "contains the entry name" do
      expect(dir_entry.to_s).to match(/Root Entry/)
    end

    context "when _sectStart is undefined" do
      it "sets _sectStart to SECT_END" do
        dir_entry.instance_variable_set(:@_sectStart, nil)
        dir_entry.to_s
        expect(dir_entry.instance_variable_get(:@_sectStart)).to eq(Rex::OLE::SECT_END)
      end
    end

    context "when _sectStart is defined" do
      it "doesn't modify _sectStart value" do
        dir_entry.instance_variable_set(:@_sectStart, Rex::OLE::SECT_FREE)
        dir_entry.to_s
        expect(dir_entry.instance_variable_get(:@_sectStart)).to eq(Rex::OLE::SECT_FREE)
      end
    end

    it "sets _cb as the unicode length of the name" do
      dir_entry.to_s
      expect(dir_entry.instance_variable_get(:@_cb)).to eq("Root Entry\x00".length * 2)
    end
  end

end
