require 'spec_helper'

RSpec.describe RubySMB::SMB1::BitField::CreateOptions do
  subject(:options) { described_class.new }

  it { is_expected.to respond_to :create_tree_connection }
  it { is_expected.to respond_to :non_directory_file }
  it { is_expected.to respond_to :synchronous_io_nonalert }
  it { is_expected.to respond_to :synchronous_io_alert }
  it { is_expected.to respond_to :no_intermediate_buffer }
  it { is_expected.to respond_to :sequential_only }
  it { is_expected.to respond_to :write_through }
  it { is_expected.to respond_to :directory_file }
  it { is_expected.to respond_to :no_compression }
  it { is_expected.to respond_to :open_for_backup_intent }
  it { is_expected.to respond_to :open_by_file_id }
  it { is_expected.to respond_to :delete_on_close }
  it { is_expected.to respond_to :random_access }
  it { is_expected.to respond_to :open_for_recovery }
  it { is_expected.to respond_to :no_ea_knowledge }
  it { is_expected.to respond_to :complete_if_oplocked }
  it { is_expected.to respond_to :open_for_free_space_query }
  it { is_expected.to respond_to :open_no_recall }
  it { is_expected.to respond_to :reserve_opfilter }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#create_tree_connection' do
    it 'is a 1-bit flag' do
      expect(options.create_tree_connection).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :create_tree_connection, 'V', 0x00000080
  end

  describe '#non_directory_file' do
    it 'is a 1-bit flag' do
      expect(options.non_directory_file).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :non_directory_file, 'V', 0x00000040
  end

  describe '#synchronous_io_nonalert' do
    it 'is a 1-bit flag' do
      expect(options.synchronous_io_nonalert).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :synchronous_io_nonalert, 'V', 0x00000020
  end

  describe '#synchronous_io_alert' do
    it 'is a 1-bit flag' do
      expect(options.synchronous_io_alert).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :synchronous_io_alert, 'V', 0x00000010
  end

  describe '#no_intermediate_buffer' do
    it 'is a 1-bit flag' do
      expect(options.no_intermediate_buffer).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :no_intermediate_buffer, 'V', 0x00000008
  end

  describe '#sequential_only' do
    it 'is a 1-bit flag' do
      expect(options.sequential_only).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :sequential_only, 'V', 0x00000004
  end

  describe '#write_through' do
    it 'is a 1-bit flag' do
      expect(options.write_through).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :write_through, 'V', 0x00000002
  end

  describe '#directory_file' do
    it 'is a 1-bit flag' do
      expect(options.directory_file).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :directory_file, 'V', 0x00000001
  end

  describe '#no_compression' do
    it 'is a 1-bit flag' do
      expect(options.no_compression).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :no_compression, 'V', 0x00008000
  end

  describe '#open_for_backup_intent' do
    it 'is a 1-bit flag' do
      expect(options.open_for_backup_intent).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :open_for_backup_intent, 'V', 0x00004000
  end

  describe '#open_by_file_id' do
    it 'is a 1-bit flag' do
      expect(options.open_by_file_id).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :open_by_file_id, 'V', 0x00002000
  end

  describe '#delete_on_close' do
    it 'is a 1-bit flag' do
      expect(options.delete_on_close).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :delete_on_close, 'V', 0x00001000
  end

  describe '#random_access' do
    it 'is a 1-bit flag' do
      expect(options.random_access).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :random_access, 'V', 0x00000800
  end

  describe '#open_for_recovery' do
    it 'is a 1-bit flag' do
      expect(options.open_for_recovery).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :open_for_recovery, 'V', 0x00000400
  end

  describe '#no_ea_knowledge' do
    it 'is a 1-bit flag' do
      expect(options.no_ea_knowledge).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :no_ea_knowledge, 'V', 0x00000200
  end

  describe '#complete_if_oplocked' do
    it 'is a 1-bit flag' do
      expect(options.complete_if_oplocked).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :complete_if_oplocked, 'V', 0x00000100
  end

  describe '#open_for_free_space_query' do
    it 'is a 1-bit flag' do
      expect(options.open_for_free_space_query).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :open_for_free_space_query, 'V', 0x00800000
  end

  describe '#open_no_recall' do
    it 'is a 1-bit flag' do
      expect(options.open_no_recall).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :open_no_recall, 'V', 0x00400000
  end

  describe '#open_reparse_point' do
    it 'is a 1-bit flag' do
      expect(options.reserve_opfilter).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :open_reparse_point, 'V', 0x00200000
  end

  describe '#reserve_opfilter' do
    it 'is a 1-bit flag' do
      expect(options.reserve_opfilter).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :reserve_opfilter, 'V', 0x00100000
  end
end
