require 'spec_helper'

RSpec.describe RubySMB::Field::SecurityDescriptor do
  subject(:descriptor) {
    struct = described_class.new
    struct.owner_sid = 'ABCD'
    struct.group_sid = 'ABCD'
    struct.sacl      = 'ABCD'
    struct.dacl      = 'ABCD'
    struct
  }

  it { is_expected.to respond_to :revision }
  it { is_expected.to respond_to :sbz1 }
  it { is_expected.to respond_to :control }
  it { is_expected.to respond_to :offset_owner }
  it { is_expected.to respond_to :offset_group }
  it { is_expected.to respond_to :offset_sacl }
  it { is_expected.to respond_to :offset_dacl }
  it { is_expected.to respond_to :owner_sid }
  it { is_expected.to respond_to :group_sid }
  it { is_expected.to respond_to :sacl }
  it { is_expected.to respond_to :dacl }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  it 'tracks the offset to the #owner_sid' do
    expect(descriptor.offset_owner).to eq descriptor.owner_sid.rel_offset
  end

  it 'tracks the offset to the #group_sid' do
    expect(descriptor.offset_group).to eq descriptor.group_sid.rel_offset
  end

  it 'tracks the offset to the #sacl' do
    expect(descriptor.offset_sacl).to eq descriptor.sacl.rel_offset
  end

  it 'tracks the offset to the #dacl' do
    expect(descriptor.offset_dacl).to eq descriptor.dacl.rel_offset
  end

  describe '#control' do
    subject(:control) { descriptor.control }

    it { is_expected.to respond_to :owner_defaulted }
    it { is_expected.to respond_to :group_defaulted }
    it { is_expected.to respond_to :dacl_present }
    it { is_expected.to respond_to :dacl_defaulted }
    it { is_expected.to respond_to :sacl_present }
    it { is_expected.to respond_to :sacl_defaulted }
    it { is_expected.to respond_to :server_security }
    it { is_expected.to respond_to :dacl_trusted }
    it { is_expected.to respond_to :dacl_computed_inheritance }
    it { is_expected.to respond_to :sacl_computed_inheritance }
    it { is_expected.to respond_to :dacl_auto_inherited }
    it { is_expected.to respond_to :sacl_auto_inherited }
    it { is_expected.to respond_to :dacl_protected }
    it { is_expected.to respond_to :sacl_protected }
    it { is_expected.to respond_to :rm_control_valid }
    it { is_expected.to respond_to :self_relative }

    describe '#self_relative' do
      it 'is a 1-bit flag' do
        expect(control.self_relative).to be_a BinData::Bit1
      end

      it_behaves_like 'bit field with one flag set', :self_relative, 'v', 0x0001
    end

    describe '#rm_control_valid' do
      it 'is a 1-bit flag' do
        expect(control.rm_control_valid).to be_a BinData::Bit1
      end

      it_behaves_like 'bit field with one flag set', :rm_control_valid, 'v', 0x0002
    end

    describe '#sacl_protected' do
      it 'is a 1-bit flag' do
        expect(control.sacl_protected).to be_a BinData::Bit1
      end

      it_behaves_like 'bit field with one flag set', :sacl_protected, 'v', 0x0004
    end

    describe '#dacl_protected' do
      it 'is a 1-bit flag' do
        expect(control.dacl_protected).to be_a BinData::Bit1
      end

      it_behaves_like 'bit field with one flag set', :dacl_protected, 'v', 0x0008
    end

    describe '#sacl_auto_inherited' do
      it 'is a 1-bit flag' do
        expect(control.sacl_auto_inherited).to be_a BinData::Bit1
      end

      it_behaves_like 'bit field with one flag set', :sacl_auto_inherited, 'v', 0x0010
    end

    describe '#dacl_auto_inherited' do
      it 'is a 1-bit flag' do
        expect(control.dacl_auto_inherited).to be_a BinData::Bit1
      end

      it_behaves_like 'bit field with one flag set', :dacl_auto_inherited, 'v', 0x0020
    end

    describe '#sacl_computed_inheritance' do
      it 'is a 1-bit flag' do
        expect(control.sacl_computed_inheritance).to be_a BinData::Bit1
      end

      it_behaves_like 'bit field with one flag set', :sacl_computed_inheritance, 'v', 0x0040
    end

    describe '#dacl_computed_inheritance' do
      it 'is a 1-bit flag' do
        expect(control.dacl_computed_inheritance).to be_a BinData::Bit1
      end

      it_behaves_like 'bit field with one flag set', :dacl_computed_inheritance, 'v', 0x0080
    end

    describe '#dacl_trusted' do
      it 'is a 1-bit flag' do
        expect(control.dacl_trusted).to be_a BinData::Bit1
      end

      it_behaves_like 'bit field with one flag set', :dacl_trusted, 'v', 0x0100
    end

    describe '#server_security' do
      it 'is a 1-bit flag' do
        expect(control.server_security).to be_a BinData::Bit1
      end

      it_behaves_like 'bit field with one flag set', :server_security, 'v', 0x0200
    end

    describe '#sacl_defaulted' do
      it 'is a 1-bit flag' do
        expect(control.sacl_defaulted).to be_a BinData::Bit1
      end

      it_behaves_like 'bit field with one flag set', :sacl_defaulted, 'v', 0x0400
    end

    describe '#sacl_present' do
      it 'is a 1-bit flag' do
        expect(control.sacl_present).to be_a BinData::Bit1
      end

      it_behaves_like 'bit field with one flag set', :sacl_present, 'v', 0x0800
    end

    describe '#dacl_defaulted' do
      it 'is a 1-bit flag' do
        expect(control.dacl_defaulted).to be_a BinData::Bit1
      end

      it_behaves_like 'bit field with one flag set', :dacl_defaulted, 'v', 0x1000
    end

    describe '#dacl_present' do
      it 'is a 1-bit flag' do
        expect(control.dacl_present).to be_a BinData::Bit1
      end

      it_behaves_like 'bit field with one flag set', :dacl_present, 'v', 0x2000
    end

    describe '#group_defaulted' do
      it 'is a 1-bit flag' do
        expect(control.group_defaulted).to be_a BinData::Bit1
      end

      it_behaves_like 'bit field with one flag set', :group_defaulted, 'v', 0x4000
    end

    describe '#owner_defaulted' do
      it 'is a 1-bit flag' do
        expect(control.owner_defaulted).to be_a BinData::Bit1
      end

      it_behaves_like 'bit field with one flag set', :owner_defaulted, 'v', 0x8000
    end
  end
end
