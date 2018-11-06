require 'spec_helper'

RSpec.describe RubySMB::GenericPacket do
  class TestPacket < RubySMB::GenericPacket
    endian :little
    uint8  :first_value,  initial_value: 0x01
    uint16 :second_value, initial_value: 0x02
    array  :array_value,  type: :dialect, read_until: :eof
  end

  class ParentTestPacket < RubySMB::GenericPacket
    endian :little
    uint8  :header
    test_packet :test_packet
  end

  subject(:test_packet) { TestPacket.new(first_value: 16, second_value: 4056, array_value: [RubySMB::SMB1::Dialect.new(dialect_string: 'test')]) }
  let(:parent_packet) { ParentTestPacket.new }

  describe '#describe class method' do
    it 'outputs a string representing the structure of the packet' do
      str = "\nFirst_value                   (Uint8)    \n"\
            "Second_value                  (Uint16le) \n"\
            'Array_value                   (Array)    '
      expect(TestPacket.describe).to eq str
    end

    it 'handles nested record structures as well' do
      str = "\nHeader                        (Uint8)    \n"\
            "TEST_PACKET                              \n"\
            "\tFirst_value                  (Uint8)    \n"\
            "\tSecond_value                 (Uint16le) \n"\
            "\tArray_value                  (Array)    "
      expect(ParentTestPacket.describe).to eq str
    end
  end

  describe '#display' do
    it 'shows the actual contents of the packet fields' do
      str = "\nFIRST_VALUE                   16\n" \
            "SECOND_VALUE                  4056\n" \
            "ARRAY_VALUE\n" \
            "\tBuffer Format ID             2\n" \
            "\tDialect Name                 test"
      expect(test_packet.display).to eq str
    end

    it 'handles nested record structures as well' do
      str = "\nHEADER                        0\n" \
            "TEST_PACKET\n" \
            "\tFirst_value                  1\n" \
            "\tSecond_value                 2\n" \
            "\tARRAY_VALUE"
      expect(parent_packet.display).to eq str
    end
  end

  describe '#read' do
    context 'when reading an SMB1 packet' do
      let(:smb1_error_packet) { RubySMB::SMB1::Packet::EmptyPacket.new }

      it 'returns the error packet instead of the asked for class' do
        expect(RubySMB::SMB1::Packet::NegotiateResponse.read(smb1_error_packet.to_binary_s)).to be_a RubySMB::SMB1::Packet::EmptyPacket
      end

      it 'raises an InvaliPacket exception if it is not a valid error packet either' do
        expect{RubySMB::SMB1::Packet::NegotiateResponse.read('a')}.to raise_error(RubySMB::Error::InvalidPacket)
      end

      it 'sets the EmptyPacket#original_command attribute to the original COMMAND' do
        packet = RubySMB::SMB1::Packet::NegotiateResponse.read(smb1_error_packet.to_binary_s)
        expect(packet.original_command).to eq RubySMB::SMB1::Packet::NegotiateResponse::COMMAND
      end
    end

    context 'when reading an SMB2 packet' do
      let(:smb2_error_packet) { RubySMB::SMB2::Packet::ErrorPacket.new }

      it 'returns the error packet instead of the asked for class' do
        expect(RubySMB::SMB2::Packet::NegotiateResponse.read(smb2_error_packet.to_binary_s)).to be_a RubySMB::SMB2::Packet::ErrorPacket
      end

      it 'raises an InvaliPacket exception if it is not a valid error packet either' do
        expect{RubySMB::SMB2::Packet::NegotiateResponse.read('a')}.to raise_error(RubySMB::Error::InvalidPacket)
      end

      it 'sets the ErrorPacket#original_command attribute to the original COMMAND' do
        packet = RubySMB::SMB2::Packet::NegotiateResponse.read(smb2_error_packet.to_binary_s)
        expect(packet.original_command).to eq RubySMB::SMB2::Packet::NegotiateResponse::COMMAND
      end
    end
  end

  describe '#valid?' do
    context 'when reading an SMB1 packet' do
      let(:packet) { RubySMB::SMB1::Packet::NegotiateResponse.new }

      it 'returns true if the packet protocol ID and header command are valid' do
        expect(packet).to be_valid
      end

      it 'returns false if the packet protocol ID is wrong' do
        packet.smb_header.protocol = RubySMB::SMB2::SMB2_PROTOCOL_ID
        expect(packet).to_not be_valid
      end

      it 'returns false if the packet header command is wrong' do
        packet.smb_header.command = RubySMB::SMB1::Commands::SMB_COM_TREE_CONNECT
        expect(packet).to_not be_valid
      end
    end

    context 'when reading an SMB2 packet' do
      let(:packet) { RubySMB::SMB2::Packet::NegotiateResponse.new }

      it 'returns true if the packet protocol ID and header command are valid' do
        expect(packet).to be_valid
      end

      it 'returns false if the packet protocol ID is wrong' do
        packet.smb2_header.protocol = RubySMB::SMB1::SMB_PROTOCOL_ID
        expect(packet).to_not be_valid
      end

      it 'returns false if the packet header command is wrong' do
        packet.smb2_header.command = RubySMB::SMB2::Commands::TREE_CONNECT
        expect(packet).to_not be_valid
      end
    end
  end
end
