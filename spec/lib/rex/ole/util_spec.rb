# -*- coding:binary -*-
require 'spec_helper'

require 'rex/ole'

describe Rex::OLE::Util do

  describe ".Hexify32array" do
    subject(:hex_array) { described_class.Hexify32array(arr) }

    context "when arr is empty" do
      let(:arr) { [] }
      it "returns empty string" do
        is_expected.to be_empty
      end
    end

    context "when arr is filled" do
      let(:arr) { [0, 1, 0x20, 0x40, 0x100, 0x200, 0x12345678] }

      it "returns an string with the hexify array" do
        is_expected.to eq('0x00000000 0x00000001 0x00000020 0x00000040 0x00000100 0x00000200 0x12345678')
      end
    end
  end

  describe ".Printable" do
    subject(:printable_buf) { described_class.Printable(buf) }

    context "when buf is empty" do
      let(:buf) { '' }
      it "returns empty string" do
        is_expected.to be_empty
      end
    end

    context "when buf only contains printable chars" do
      let(:buf) { 'abcdefghijklmnopqrstuvwxyz1234567890!@#$%^&*()' }

      it "returns the same string" do
        is_expected.to eq(buf)
      end
    end

    context "when buf contains no printable chars" do
      let(:buf) { "abcde\x88" }

      it "returns hex representation for non printable chars" do
        is_expected.to eq('abcde\\x88')
      end
    end
  end

  describe ".set_endian" do
    subject(:set_endian) { described_class.set_endian(endian) }
    let(:endian) { Rex::OLE::LITTLE_ENDIAN }

    it "sets the endian field" do
      set_endian
      expect(described_class.instance_variable_get(:@endian)).to eq(0xfffe)
    end

    it "returns the set endianness" do
      is_expected.to eq(0xfffe)
    end
  end

  describe ".get64" do
    subject(:quad_word) { described_class.get64(buf, offset) }

    context "when buf is empty" do
      let(:buf) { '' }
      let(:offset) { 0 }

      it "raises a null dereference exception" do
        expect { quad_word }.to raise_error(NoMethodError)
      end
    end

    context "when buf is shorter than offset" do
      let(:buf) { "\x12\x34\x56\x78\x12\x34\x56\x78" }
      let(:offset) { 8 }

      it "raises a null dereference exceptioon" do
        expect { quad_word }.to raise_error(NoMethodError)
      end
    end

    context "when @endian is little endian" do
      let(:buf) { "\x00\x11\x22\x33\x44\x55\x66\x77\x88" }
      let(:offset) { 1 }

      it "returns the little endian quad word at offset" do
        described_class.set_endian(Rex::OLE::LITTLE_ENDIAN)
        is_expected.to eq(0x8877665544332211)
      end
    end

    context "when @endian is big endian" do
      let(:buf) { "\x00\x11\x22\x33\x44\x55\x66\x77\x88" }
      let(:offset) { 1 }

      it "returns the big endian quad word at offset" do
        described_class.set_endian(Rex::OLE::BIG_ENDIAN)
        is_expected.to eq(0x1122334455667788)
      end
    end
  end

  describe ".pack64" do
    subject(:packed_quad_word) { described_class.pack64(value) }
    let(:value) { 0x1122334455667788 }

    context "when @endian is little endian" do
      it "returns the packed little endian quad word" do
        described_class.set_endian(Rex::OLE::LITTLE_ENDIAN)
        is_expected.to eq("\x88\x77\x66\x55\x44\x33\x22\x11")
      end
    end

    context "when @endian is big endian" do
      it "returns the packed big endian quad word" do
        described_class.set_endian(Rex::OLE::BIG_ENDIAN)
        is_expected.to eq("\x11\x22\x33\x44\x55\x66\x77\x88")
      end
    end
  end

  describe ".get32" do
    subject(:word) { described_class.get32(buf, offset) }

    context "when buf is empty" do
      let(:buf) { '' }
      let(:offset) { 0 }

      it "returns nil" do
        is_expected.to be_nil
      end
    end

    context "when buf is shorter than offset" do
      let(:buf) { "\x12\x34\x56" }
      let(:offset) { 4 }

      it "raises a null dereference exceptioon" do
        expect { word }.to raise_error(NoMethodError)
      end
    end

    context "when @endian is little endian" do
      let(:buf) { "\x00\x11\x22\x33\x44\x55\x66\x77\x88" }
      let(:offset) { 1 }

      it "returns the little endian word at offset" do
        described_class.set_endian(Rex::OLE::LITTLE_ENDIAN)
        is_expected.to eq(0x44332211)
      end
    end

    context "when @endian is big endian" do
      let(:buf) { "\x00\x11\x22\x33\x44\x55\x66\x77\x88" }
      let(:offset) { 1 }

      it "returns the big endian word at offset" do
        described_class.set_endian(Rex::OLE::BIG_ENDIAN)
        is_expected.to eq(0x11223344)
      end
    end
  end

  describe ".pack32" do
    subject(:packed_word) { described_class.pack32(value) }
    let(:value) { 0x11223344 }

    context "when @endian is little endian" do
      it "returns the packed little endian word" do
        described_class.set_endian(Rex::OLE::LITTLE_ENDIAN)
        is_expected.to eq("\x44\x33\x22\x11")
      end
    end

    context "when @endian is big endian" do
      it "returns the packed big endian word at offset" do
        described_class.set_endian(Rex::OLE::BIG_ENDIAN)
        is_expected.to eq("\x11\x22\x33\x44")
      end
    end
  end

  describe ".get32array" do
    subject(:word_array) { described_class.get32array(buf) }

    context "when buf is empty" do
      let(:buf) { '' }

      it "returns an empty array" do
        is_expected.to eq([])
      end
    end

    context "when buf isn't empty" do
      let(:buf) { "\x11\x22\x33\x44\x55\x66\x77\x88" }

      context "when @endian is little endian" do
        it "unpacks an array of little endian words" do
          described_class.set_endian(Rex::OLE::LITTLE_ENDIAN)
          is_expected.to eq([0x44332211, 0x88776655])
        end
      end

      context "when @endian is big endian" do
        it "unpacks an array of big endian words" do
          described_class.set_endian(Rex::OLE::BIG_ENDIAN)
          is_expected.to eq([0x11223344, 0x55667788])
        end
      end
    end
  end

  describe ".pack32array" do
    subject(:packed_word) { described_class.pack32array(arr) }

    context "when arr is empty" do
      let(:arr) { [] }
      it "returns an empty string" do
        is_expected.to eq('')
      end
    end

    context "when arr isn't empty" do
      let(:arr) { [0x11223344, 0x55667788] }

      context "when @endian is little endian" do
        it "returns the little endian words array packed" do
          described_class.set_endian(Rex::OLE::LITTLE_ENDIAN)
          is_expected.to eq("\x44\x33\x22\x11\x88\x77\x66\x55")
        end
      end

      context "when @endian is big endian" do
        it "returns the big endian words array packed" do
          described_class.set_endian(Rex::OLE::BIG_ENDIAN)
          is_expected.to eq("\x11\x22\x33\x44\x55\x66\x77\x88")
        end
      end
    end

  end

  describe ".get16" do
    subject(:half_word) { described_class.get16(buf, offset) }

    context "when buf is empty" do
      let(:buf) { '' }
      let(:offset) { 0 }

      it "returns nil" do
        is_expected.to be_nil
      end
    end

    context "when buf is shorter than offset" do
      let(:buf) { "\x12\x34" }
      let(:offset) { 4 }

      it "raises a null dereference exceptioon" do
        expect { half_word }.to raise_error(NoMethodError)
      end
    end

    context "when @endian is little endian" do
      let(:buf) { "\x00\x11\x22\x33\x44" }
      let(:offset) { 1 }

      it "returns the little endian half word at offset" do
        described_class.set_endian(Rex::OLE::LITTLE_ENDIAN)
        is_expected.to eq(0x2211)
      end
    end

    context "when @endian is big endian" do
      let(:buf) { "\x00\x11\x22\x33\x44" }
      let(:offset) { 1 }

      it "returns the big endian word at offset" do
        described_class.set_endian(Rex::OLE::BIG_ENDIAN)
        is_expected.to eq(0x1122)
      end
    end
  end

  describe ".pack16" do
    subject(:packed_word) { described_class.pack16(value) }
    let(:value) { 0x1122 }

    context "when @endian is little endian" do
      it "returns the packed little endian word" do
        described_class.set_endian(Rex::OLE::LITTLE_ENDIAN)
        is_expected.to eq("\x22\x11")
      end
    end

    context "when @endian is big endian" do
      it "returns the packed big endian word at offset" do
        described_class.set_endian(Rex::OLE::BIG_ENDIAN)
        is_expected.to eq("\x11\x22")
      end
    end
  end

  describe ".get8" do
    subject(:byte) { described_class.get8(buf, offset) }

    context "when buf is empty" do
      let(:buf) { '' }
      let(:offset) { 0 }

      it "returns nil" do
        is_expected.to be_nil
      end
    end

    context "when buf is shorter than offset" do
      let(:buf) { "\x12\x34" }
      let(:offset) { 4 }

      it "raises a null dereference exceptioon" do
        expect { byte }.to raise_error(NoMethodError)
      end
    end

    let(:buf) { "\x00\x11\x22" }
    let(:offset) { 1 }

    it "returns the byte at offset" do
      is_expected.to eq(0x11)
    end
  end

  describe ".pack8" do
    subject(:packed_byte) { described_class.pack8(value) }
    let(:value) { 0x11 }

    it "returns the packed byte" do
      is_expected.to eq("\x11")
    end
  end

  describe ".getUnicodeString" do
    subject(:unicode_string) { described_class.getUnicodeString(buf) }
    let(:buf) { "T\x00h\x00i\x00s\x00 \x00i\x00s\x00 \x00a\x00n\x00 \x00u\x00n\x00i\x00c\x00o\x00d\x00e\x00 \x00s\x00t\x00r\x00i\x00n\x00g\x00" }

    it "unpacks unicode string" do
      is_expected.to eq('This is an unicode string')
    end

    context "when buf contains unicode nulls" do
      let(:buf) { "T\x00h\x00\x00i\x00s\x00" }

      it "unpacks unicode string until null" do
        is_expected.to eq('Th')
      end
    end
  end

  describe ".putUnicodeString" do
    subject(:packed_byte) { described_class.putUnicodeString(buf) }
    let(:buf) { 'A' * 32 }

    it "returns the unicode version of the string" do
      is_expected.to eq("A\x00" * 32)
    end

    context "when buf is shorter than 32" do
      let(:buf) { 'A' * 30 }
      it "adds null byte padding" do
        is_expected.to eq(("A\x00" * 30) + "\x00\x00\x00\x00")
      end
    end
  end

  describe ".name_is_valid" do
    subject(:valid_name) { described_class.name_is_valid(name) }

    context "when name length is greater than 31" do
      let(:name) { 'A' * 32 }
      it "returns nil" do
        is_expected.to be_nil
      end
    end

    context "when name contains [0x00..0x1f] chars" do
      let(:name) { "ABCDE\x1f" }
      it "returns nil" do
        is_expected.to be_nil
      end
    end

    context "when name doesn't contain [0x00..0x1f] chars" do
      let(:name) { "ABCDE\x88" }
      it "returns true" do
        is_expected.to be_truthy
      end
    end
  end
end
