# -*- coding:binary -*-
require 'spec_helper'

require 'rex/ole'

describe Rex::OLE::Header do
  before(:each) do
    Rex::OLE::Util.set_endian(Rex::OLE::LITTLE_ENDIAN)
  end

  subject(:header) do
    described_class.new
  end

  describe ".new" do
    it "returns a Rex::OLE::Header instance" do
      expect(described_class.new).to be_a(Rex::OLE::Header)
    end

    it { expect(header.instance_variable_get(:@_abSig)).to eq(Rex::OLE::SIG) }
    it { expect(header.instance_variable_get(:@_clid)).to be_a(Rex::OLE::CLSID) }
    it { expect(header.instance_variable_get(:@_uByteOrder)).to eq(Rex::OLE::LITTLE_ENDIAN) }
    it { expect(header.instance_variable_get(:@_uMinorVersion)).to eq(0x3e) }
    it { expect(header._uMajorVersion).to eq(0x03) }
    it { expect(header.instance_variable_get(:@_uSectorShift)).to eq(9) }
    it { expect(header._uMiniSectorShift).to eq(6) }
    it { expect(header.instance_variable_get(:@_csectDir)).to be_nil }
    it { expect(header._csectFat).to be_nil }
    it { expect(header._sectDirStart).to be_nil }
    it { expect(header.instance_variable_get(:@_signature)).to eq(0) }
    it { expect(header._ulMiniSectorCutoff).to eq(0x1000) }
    it { expect(header._sectMiniFatStart).to eq(Rex::OLE::SECT_END) }
    it { expect(header._csectMiniFat).to eq(0) }
    it { expect(header._sectDifStart).to eq(Rex::OLE::SECT_END) }
    it { expect(header._csectDif).to eq(0) }
    it { expect(header._sectFat).to be_an(Array) }
    it { expect(header.instance_variable_get(:@_sectFat)).to be_empty }
    it { expect(header.sector_size).to eq(1 << 9) }
    it { expect(header.mini_sector_size).to eq(1 << 6) }
    it { expect(header.idx_per_sect).to eq((1 << 9) / 4) }
  end

  describe "#set_defaults" do
    it "sets OLECF signature" do
      header.set_defaults
      expect(header.instance_variable_get(:@_abSig)).to eq(Rex::OLE::SIG)
    end

    it "setup a class identifier (guid)" do
      header.set_defaults
      expect(header.instance_variable_get(:@_clid)).to be_a(Rex::OLE::CLSID)
    end

    it "sets byte order identifier as little endian" do
      header.set_defaults
      expect(header.instance_variable_get(:@_uByteOrder)).to eq(Rex::OLE::LITTLE_ENDIAN)
    end

    it "sets the minor version to 0x3e" do
      header.set_defaults
      expect(header.instance_variable_get(:@_uMinorVersion)).to eq(0x3e)
    end

    it "sets the major version to 0x3" do
      header.set_defaults
      expect(header._uMajorVersion).to eq(0x03)
    end

    it "sets the size of sectors to 9" do
      header.set_defaults
      expect(header.instance_variable_get(:@_uSectorShift)).to eq(9)
    end

    it "sets the size of mini-sectors to 6" do
      header.set_defaults
      expect(header._uMiniSectorShift).to eq(6)
    end

    it "sets the number of sectors in the directory chain to nil" do
      header.set_defaults
      expect(header.instance_variable_get(:@_csectDir)).to be_nil
    end

    it "sets the number of sectors in the FAT chain to nil" do
      header.set_defaults
      expect(header._csectFat).to be_nil
    end

    it "sets first sector in the directory chain to nil" do
      header.set_defaults
      expect(header._sectDirStart).to be_nil
    end

    it "sets the signature used for transactioning to zero" do
      header.set_defaults
      expect(header.instance_variable_get(:@_signature)).to eq(0)
    end

    it "sets the maximum size of mini-streams to 4096" do
      header.set_defaults
      expect(header._ulMiniSectorCutoff).to eq(0x1000)
    end

    it "sets the first sector in the mini-FAT chain to end of chain" do
      header.set_defaults
      expect(header._sectMiniFatStart).to eq(Rex::OLE::SECT_END)
    end

    it "sets the number of sectors in the mini-FAT chain to 0" do
      header.set_defaults
      expect(header._csectMiniFat).to eq(0)
    end

    it "sets the first sector in the DIF chain to end of chain" do
      header.set_defaults
      expect(header._sectDifStart).to eq(Rex::OLE::SECT_END)
    end

    it "sets the number of sectors in the DIF chain to 0" do
      header.set_defaults
      expect(header._csectDif).to eq(0)
    end

    it "creates an array for the sectors of the first 109 FAT sectors" do
      header.set_defaults
      expect(header._sectFat).to be_an(Array)
    end

    it "creates an empty array for the FAT sectors" do
      header.set_defaults
      expect(header.instance_variable_get(:@_sectFat)).to be_empty
    end
  end

  describe "#to_s" do
    subject(:header_string) { header.to_s }

    it "returns an String" do
      expect(header_string).to be_an(String)
    end

    it "starts with {" do
      expect(header_string).to start_with('{')
    end

    it "ends with {" do
      expect(header_string).to end_with('}')
    end

    it "includes the OLECF signature" do
      expect(header_string).to match(/_abSig => "\\xd0\\xcf\\x11\\xe0\\xa1\\xb1\\x1a\\xe1"/)
    end

    it "includes the class identifier value" do
      expect(header_string).to match(/_clid => 00000000-0000-0000-0000-000000000000/)
    end

    it "includes the minor version value" do
      expect(header_string).to match(/_uMinorVersion => 0x003e/)
    end

    it "includes the major version value" do
      expect(header_string).to match(/_uMajorVersion => 0x0003/)
    end

    it "includes the byte order identifier value" do
      expect(header_string).to match(/_uByteOrder => 0xfffe/)
    end

    it "includes the size of sectors value" do
      expect(header_string).to match(/_uSectorShift => 0x0009/)
    end

    it "includes the size of mini-sectors value" do
      expect(header_string).to match(/_uMiniSectorShift => 0x0006/)
    end

    it "includes the number of sectors in the directory chain" do
      expect(header_string).to match(/_csectDir => UNALLOCATED/)
    end

    it "includes the number of sectors in the FAT chain" do
      expect(header_string).to match(/_csectFat => UNALLOCATED/)
    end

    it "includes the first sector in the directory chain" do
      expect(header_string).to match(/_sectDirStart => UNALLOCATED/)
    end

    it "includes the signature used for transactioning" do
      expect(header_string).to match(/_signature => 0x00000000/)
    end

    it "includes the maximum size of mini-streams" do
      expect(header_string).to match(/_uMiniSectorCutoff => 0x00001000/)
    end

    it "includes the first sector in the mini-FAT chain value" do
      expect(header_string).to match(/_sectMiniFatStart => 0xfffffffe/)
    end

    it "includes the number of sectors in the mini-FAT chain" do
      expect(header_string).to match(/_csectMiniFat => 0x00000000/)
    end

    it "includes the first sector in the DIF chain value" do
      expect(header_string).to match(/_sectDifStart => 0xfffffffe/)
    end

    it "includes the number of sectors in the DIF chain" do
      expect(header_string).to match(/_csectDif => 0x00000000/)
    end
  end

  describe "#read" do
    context "when reading empty header" do
      let(:empty_fd) do
        s = ''
        StringIO.new(s, 'rb')
      end

      it "raises NoMethodError" do
        expect { header.read(empty_fd) }.to raise_error(NoMethodError)
      end
    end


    context "when reading header with invalid signature" do
      let(:incorrect_fd) do
        s = 'A' * Rex::OLE::HDR_SZ
        StringIO.new(s, 'rb')
      end

      it "raises RuntimeError" do
        expect { header.read(incorrect_fd) }.to raise_error(RuntimeError)
      end
    end

    context "when reading header with valid signature" do
      let(:correct_fd) do
        hdr = ""
        hdr << Rex::OLE::SIG
        hdr << 'A' * 16 # @_clid
        hdr << 'BB' # @_uMinorVersion
        hdr << 'CC' # @_uMajorVersion
        hdr << "\xfe\xff" # @_uByteOrder
        hdr << 'EE' # @_uSectorShift
        hdr << 'FF' # @_uMiniSectorShift
        hdr << '123456' # padding
        hdr << 'GGGG' # @_csectDir
        hdr << 'HHHH' # @_csectFat
        hdr << 'IIII' # @_sectDirStart
        hdr << 'JJJJ' # @_signature
        hdr << 'KKKK' # @_ulMiniSectorCutoff
        hdr << 'LLLL' # @_sectMiniFatStart
        hdr << 'MMMM' # @_csectMiniFat
        hdr << 'NNNN' # @_sectDifStart
        hdr << 'OOOO' # @_csectDif
        hdr << 'P' * 109 * 4 # @_sectFat

        StringIO.new(hdr, 'rb')
      end

      it "sets clsid from input" do
        header.read(correct_fd)
        expect(header.instance_variable_get(:@_clid).to_s).to eq("41414141-4141-4141-4141-414141414141")
      end

      it "sets minor version from input" do
        header.read(correct_fd)
        expect(header.instance_variable_get(:@_uMinorVersion)).to eq(0x4242)
      end

      it "sets major version from input" do
        header.read(correct_fd)
        expect(header._uMajorVersion).to eq(0x4343)
      end

      it "sets byte order from input" do
        header.read(correct_fd)
        expect(header.instance_variable_get(:@_uByteOrder)).to eq(Rex::OLE::LITTLE_ENDIAN)
      end

      it "sets the size of sectors from input" do
        header.read(correct_fd)
        expect(header.instance_variable_get(:@_uSectorShift)).to eq(0x4545)
      end

      it "sets the size of mini-sectors from input" do
        header.read(correct_fd)
        expect(header._uMiniSectorShift).to eq(0x4646)
      end

      it "sets the number of sectors in the directory chain from input" do
        header.read(correct_fd)
        expect(header.instance_variable_get(:@_csectDir)).to eq(0x47474747)
      end

      it "sets the number of sectors in the FAT chain from input" do
        header.read(correct_fd)
        expect(header._csectFat).to eq(0x48484848)
      end

      it "sets the first sector in the directory chain from input" do
        header.read(correct_fd)
        expect(header._sectDirStart).to eq(0x49494949)
      end

      it "sets the signature used for transactioning from input" do
        header.read(correct_fd)
        expect(header.instance_variable_get(:@_signature)).to eq(0x4a4a4a4a)
      end

      it "sets the maximum size of mini-streams from input" do
        header.read(correct_fd)
        expect(header._ulMiniSectorCutoff).to eq(0x4b4b4b4b)
      end

      it "sets the first sector in the mini-FAT chain from input" do
        header.read(correct_fd)
        expect(header._sectMiniFatStart).to eq(0x4c4c4c4c)
      end

      it "sets the number of sectors in the mini-FAT chain from input" do
        header.read(correct_fd)
        expect(header._csectMiniFat).to eq(0x4d4d4d4d)
      end

      it "sets the first sector in the DIF chain from input" do
        header.read(correct_fd)
        expect(header._sectDifStart).to eq(0x4e4e4e4e)
      end

      it "sets the number of sectors in the DIF chain from input" do
        header.read(correct_fd)
        expect(header._csectDif).to eq(0x4f4f4f4f)
      end

      it "creates an array for the FAT sectors from input" do
        header.read(correct_fd)
        expect(header._sectFat.length).to eq(109)
      end
    end
  end

  describe "#write" do
    context "when default header" do
      it "writes 76 bytes" do
        fd = StringIO.new('', 'wb')
        header.write(fd)
        expect(fd.string.length).to eq(76)
      end
    end
  end
end
