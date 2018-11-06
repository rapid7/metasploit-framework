require 'spec_helper'
require 'securerandom'

RSpec.describe RubySMB::SMB2::File do
  let(:sock) { double('Socket', peeraddr: '192.168.1.5') }
  let(:dispatcher) { RubySMB::Dispatcher::Socket.new(sock) }

  let(:client) { RubySMB::Client.new(dispatcher, username: 'msfadmin', password: 'msfadmin') }
  let(:tree_id) { 2049 }
  let(:path) { '\\192.168.1.1\example' }
  let(:connect_response) {
    packet = RubySMB::SMB2::Packet::TreeConnectResponse.new
    packet.smb2_header.tree_id = tree_id
    packet.maximal_access.read("\xff\x01\x1f\x00")
    packet.share_type = 0x01
    packet
  }

  let(:disco_req) { RubySMB::SMB2::Packet::TreeDisconnectRequest.new }
  let(:disco_resp) { RubySMB::SMB2::Packet::TreeDisconnectResponse.new }
  let(:tree) { RubySMB::SMB2::Tree.new(client: client, share: path, response: connect_response) }
  let(:file_id) { RubySMB::Field::Smb2Fileid.read('\x6d\x01\x00\x00\x00\x00\x00\x00\x\x01\x00\x00\x00\xff\xff\xff\xff') }
  let(:time) { DateTime.now }
  let(:create_response) {
    RubySMB::SMB2::Packet::CreateResponse.new(
      file_id: file_id,
      end_of_file: 108,
      allocation_size: 112,
      last_access: time,
      last_change: time,
      last_write: time
    )
  }

  subject(:file) { described_class.new(name: 'short.txt', response: create_response, tree: tree) }

  it { is_expected.to respond_to :attributes }
  it { is_expected.to respond_to :guid }
  it { is_expected.to respond_to :last_access }
  it { is_expected.to respond_to :last_change }
  it { is_expected.to respond_to :last_write }
  it { is_expected.to respond_to :name }
  it { is_expected.to respond_to :size }
  it { is_expected.to respond_to :size_on_disk }
  it { is_expected.to respond_to :tree }

  it 'pulls the attributes from the response packet' do
    expect(file.attributes).to eq create_response.file_attributes
  end

  it 'pulls the GUID from the response fileid' do
    expect(file.guid).to eq create_response.file_id
  end

  it 'pulls the timestamps from the response packet' do
    expect(file.last_access).to eq create_response.last_access.to_datetime
  end

  it 'pulls the size from the response packet' do
    expect(file.size).to eq create_response.end_of_file
  end

  it 'pulls the size_on_disk from the response packet' do
    expect(file.size_on_disk).to eq create_response.allocation_size
  end

  describe '#set_header_fields' do
    let(:request) { RubySMB::SMB2::Packet::ReadRequest.new }
    it 'calls the set_header_field method from the Tree' do
      expect(tree).to receive(:set_header_fields).with(request).and_call_original
      file.set_header_fields(request)
    end

    it 'sets the packet file_id from the guid' do
      expect(file.set_header_fields(request).file_id).to eq file.guid
    end
  end

  describe '#read_packet' do
    it 'creates a new ReadRequest packet' do
      expect(RubySMB::SMB2::Packet::ReadRequest).to receive(:new).and_call_original
      file.read_packet
    end

    it 'calls #set_header_fields' do
      expect(file).to receive(:set_header_fields).and_call_original
      file.read_packet
    end

    it 'sets the read_length of the packet' do
      expect(file.read_packet(read_length: 55).read_length).to eq 55
    end

    it 'sets the offset of the packet' do
      expect(file.read_packet(offset: 55).offset).to eq 55
    end
  end

  describe '#read' do
    context 'for a small file' do
      let(:small_read) { file.read_packet(read_length: 108) }
      let(:small_response) {
        response = RubySMB::SMB2::Packet::ReadResponse.new(data_length: 9, buffer: 'fake data')
        response.smb2_header.command = RubySMB::SMB2::Commands::READ
        response
      }

      before :example do
        allow(file).to receive(:read_packet)
        allow(client).to receive(:send_recv)
        allow(RubySMB::SMB2::Packet::ReadResponse).to receive(:read).and_return(small_response)
      end

      it 'uses a single packet to read the entire file' do
        expect(file).to receive(:read_packet).with(read_length: 108, offset: 0).and_return(small_read)
        expect(client).to receive(:send_recv).with(small_read).and_return 'fake data'
        expect(RubySMB::SMB2::Packet::ReadResponse).to receive(:read).with('fake data').and_return(small_response)
        expect(file.read).to eq 'fake data'
      end

      context 'when the response is not valid' do
        it 'raise an InvalidPacket exception' do
          small_response.smb2_header.command = RubySMB::SMB2::Commands::LOGOFF
          expect { file.read }.to raise_error(RubySMB::Error::InvalidPacket)
        end
      end

      context 'when the response status code is not STATUS_SUCCESS' do
        it 'raise an UnexpectedStatusCode exception' do
          small_response.smb2_header.nt_status = WindowsError::NTStatus::STATUS_INVALID_HANDLE.value
          expect { file.read }.to raise_error(RubySMB::Error::UnexpectedStatusCode)
        end
      end
    end

    context 'for a larger file' do
      let(:big_read) { file.read_packet(read_length: 108) }
      let(:big_response) {
        response = RubySMB::SMB2::Packet::ReadResponse.new(data_length: 9, buffer: 'fake data')
        response.smb2_header.command = RubySMB::SMB2::Commands::READ
        response
      }

      before :example do
        allow(file).to receive(:read_packet)
        allow(client).to receive(:send_recv)
        allow(RubySMB::SMB2::Packet::ReadResponse).to receive(:read).and_return(big_response)
      end

      it 'uses a multiple packet to read the file in chunks' do
        expect(file).to receive(:read_packet).once.with(read_length: described_class::MAX_PACKET_SIZE, offset: 0).and_return(big_read)
        expect(file).to receive(:read_packet).once.with(read_length: described_class::MAX_PACKET_SIZE, offset: described_class::MAX_PACKET_SIZE).and_return(big_read)
        expect(client).to receive(:send_recv).twice.and_return 'fake data'
        expect(RubySMB::SMB2::Packet::ReadResponse).to receive(:read).twice.with('fake data').and_return(big_response)
        file.read(bytes: (described_class::MAX_PACKET_SIZE * 2))
      end

      context 'when the second response is not valid' do
        it 'raise an InvalidPacket exception' do
          allow(file).to receive(:read_packet).with(read_length: described_class::MAX_PACKET_SIZE, offset: described_class::MAX_PACKET_SIZE) do
            big_response.smb2_header.command = RubySMB::SMB2::Commands::LOGOFF
          end
          expect { file.read(bytes: (described_class::MAX_PACKET_SIZE * 2)) }.to raise_error(RubySMB::Error::InvalidPacket)
        end
      end

      context 'when the second response status code is not STATUS_SUCCESS' do
        it 'raise an UnexpectedStatusCode exception' do
          allow(file).to receive(:read_packet).with(read_length: described_class::MAX_PACKET_SIZE, offset: described_class::MAX_PACKET_SIZE) do
            big_response.smb2_header.nt_status = WindowsError::NTStatus::STATUS_INVALID_HANDLE.value
          end
          expect { file.read(bytes: (described_class::MAX_PACKET_SIZE * 2)) }.to raise_error(RubySMB::Error::UnexpectedStatusCode)
        end
      end
    end
  end

  describe '#append' do
    it 'call #write with offset set to the end of the file' do
      expect(file).to receive(:write).with(data:'test', offset: file.size)
      file.append(data:'test')
    end
  end

  describe '#write_packet' do
    it 'calls #set_header_fields with the newly created packet' do
      expect(file).to receive(:set_header_fields).and_call_original
      file.write_packet
    end

    it 'sets the offset on the packet' do
      expect(file.write_packet(offset:5).write_offset).to eq 5
    end

    it 'sets the buffer on the packet' do
      expect(file.write_packet(data:'hello').buffer).to eq 'hello'
    end
  end

  describe '#write' do
    let(:write_response) { RubySMB::SMB2::Packet::WriteResponse.new }
    context 'for a small write' do
      it 'sends a single packet' do
        expect(client).to receive(:send_recv).once.and_return(write_response.to_binary_s)
        file.write(data: 'test')
      end
    end

    context 'for a large write' do
      it 'sends multiple packets' do
        expect(client).to receive(:send_recv).twice.and_return(write_response.to_binary_s)
        file.write(data: SecureRandom.random_bytes(described_class::MAX_PACKET_SIZE + 1))
      end
    end

    it 'raises an InvalidPacket exception if the response is not valid' do
      allow(client).to receive(:send_recv)
      allow(RubySMB::SMB2::Packet::WriteResponse).to receive(:read).and_return(write_response)
      allow(write_response).to receive(:valid?).and_return(false)
      expect { file.write(data: 'test') }.to raise_error(RubySMB::Error::InvalidPacket)
    end
  end

  describe '#delete_packet' do
    it 'creates a new SetInfoRequest packet' do
      expect(RubySMB::SMB2::Packet::SetInfoRequest).to receive(:new).and_call_original
      file.delete_packet
    end

    it 'calls #set_header_fields' do
      expect(file).to receive(:set_header_fields).and_call_original
      file.delete_packet
    end

    it 'sets the file_info_class of the packet' do
      expect(file.delete_packet.file_info_class).to eq RubySMB::Fscc::FileInformation::FILE_DISPOSITION_INFORMATION
    end

    it 'sets the delete_pending field to 1' do
      expect(file.delete_packet.buffer.delete_pending).to eq 1
    end
  end

  describe '#delete' do
    context 'for a small file' do
      let(:small_delete) { file.delete_packet }
      let(:small_response) { RubySMB::SMB2::Packet::SetInfoResponse.new }

      it 'uses a single packet to delete the entire file' do
        expect(file).to receive(:delete_packet).and_return(small_delete)
        expect(client).to receive(:send_recv).with(small_delete).and_return 'raw_response'
        expect(RubySMB::SMB2::Packet::SetInfoResponse).to receive(:read).with('raw_response').and_return(small_response)
        expect(file.delete).to eq WindowsError::NTStatus::STATUS_SUCCESS
      end

      it 'raises an InvalidPacket exception if the response is not valid' do
        allow(file).to receive(:delete_packet)
        allow(client).to receive(:send_recv)
        allow(RubySMB::SMB2::Packet::SetInfoResponse).to receive(:read).and_return(small_response)
        allow(small_response).to receive(:valid?).and_return(false)
        expect { file.delete }.to raise_error(RubySMB::Error::InvalidPacket)
      end
    end
  end

  describe '#rename_packet' do
    it 'creates a new SetInfoRequest packet' do
      expect(RubySMB::SMB2::Packet::SetInfoRequest).to receive(:new).and_call_original
      file.rename_packet('new_file.txt')
    end

    it 'calls #set_header_fields' do
      expect(file).to receive(:set_header_fields).and_call_original
      file.rename_packet('new_file.txt')
    end

    it 'sets the file_info_class of the packet' do
      expect(file.rename_packet('new_file.txt').file_info_class).to eq RubySMB::Fscc::FileInformation::FILE_RENAME_INFORMATION
    end

    it 'sets the file_name field to the unicode-encoded new file name' do
      filename = "new_file.txt"
      expect(file.rename_packet(filename).buffer.file_name).to eq filename.encode('UTF-16LE').force_encoding('ASCII-8BIT')
    end
  end

  describe '#rename' do
    context 'for a small file' do
      let(:small_rename) { file.rename_packet('new_file.txt') }
      let(:small_response) { RubySMB::SMB2::Packet::SetInfoResponse.new }

      it 'uses a single packet to rename the entire file' do
        expect(file).to receive(:rename_packet).and_return(small_rename)
        expect(client).to receive(:send_recv).with(small_rename).and_return 'raw_response'
        expect(RubySMB::SMB2::Packet::SetInfoResponse).to receive(:read).with('raw_response').and_return(small_response)
        expect(file.rename('new_file.txt')).to eq WindowsError::NTStatus::STATUS_SUCCESS
      end

      it 'raises an InvalidPacket exception if the response is not valid' do
        allow(client).to receive(:send_recv)
        allow(RubySMB::SMB2::Packet::SetInfoResponse).to receive(:read).and_return(small_response)
        allow(small_response).to receive(:valid?).and_return(false)
        expect { file.rename('new_file.txt') }.to raise_error(RubySMB::Error::InvalidPacket)
      end
    end
  end

  describe '#close' do
    let(:request)  { double('CloseRequest') }
    let(:response) { double('CloseResponse') }
    let(:raw_response) { double('Raw response') }

    before :example do
      allow(RubySMB::SMB2::Packet::CloseRequest).to receive(:new).and_return(request)
      allow(file).to receive(:set_header_fields).and_return(request)
      allow(client).to receive(:send_recv).and_return(raw_response)
      allow(RubySMB::SMB2::Packet::CloseResponse).to receive(:read).and_return(response)
      allow(response).to receive(:valid?).and_return(true)
      allow(response).to receive(:status_code).and_return(WindowsError::NTStatus::STATUS_SUCCESS)
    end

    it 'creates a new SMB2 CloseRequest packet' do
      expect(RubySMB::SMB2::Packet::CloseRequest).to receive(:new)
      file.close
    end

    it 'calls Tree #set_header_fields to set SetFileInformationRequest headers' do
      expect(file).to receive(:set_header_fields).with(request)
      file.close
    end

    it 'calls Client #send_recv with the expected request' do
      expect(client).to receive(:send_recv).with(request)
      file.close
    end

    it 'parses the response as a SMB2 CloseResponse packet' do
      expect(RubySMB::SMB2::Packet::CloseResponse).to receive(:read).with(raw_response)
      file.close
    end

    it 'raises an InvalidPacket exception if the response is not valid' do
      allow(response).to receive(:valid?).and_return(false)
      smb2_header = double('SMB2 Header')
      allow(response).to receive(:smb2_header).and_return(smb2_header)
      allow(smb2_header).to receive_messages(:protocol => nil, :command => nil)
      expect { file.close }.to raise_error(RubySMB::Error::InvalidPacket)
    end

    it 'raises an UnexpectedStatusCode exception if the response status code is not STATUS_SUCCESS' do
      allow(response).to receive(:status_code).and_return(WindowsError::NTStatus::STATUS_OBJECT_NAME_NOT_FOUND)
      expect { file.close }.to raise_error(RubySMB::Error::UnexpectedStatusCode)
    end

    it 'returns the response status code' do
      expect(file.close).to eq WindowsError::NTStatus::STATUS_SUCCESS
    end
  end

  describe '#send_recv_read' do
    let(:read_data) { 'read data' }
    let(:raw_response) { double('fake raw response data') }
    let(:read_response) {
      res = RubySMB::SMB2::Packet::ReadResponse.new
      res.data_length = read_data.size
      res.buffer = read_data
      res
    }

    before :example do
      allow(client).to receive(:send_recv).and_return(raw_response)
      allow(RubySMB::SMB2::Packet::ReadResponse).to receive(:read).with(raw_response).and_return(read_response)
    end

    context 'when the number of bytes to read is not provided' do
      it 'reads 0 bytes by default' do
        expect(file).to receive(:read_packet).with(read_length: 0, offset: 0).once.and_call_original
        file.send_recv_read
      end
    end

    it 'only reads the number of bytes provided as argument' do
      bytes = 5
      expect(file).to receive(:read_packet).with(read_length: bytes, offset: 0).once.and_call_original
      file.send_recv_read(read_length: bytes)
    end

    it 'reads from the offset provided as argument' do
      offset = 3
      expect(file).to receive(:read_packet).with(read_length: 0, offset: offset).once.and_call_original
      file.send_recv_read(offset: offset)
    end

    it 'calls Client #send_recv with the expected request' do
      request = double('Request')
      allow(file).to receive(:read_packet).and_return(request)
      expect(client).to receive(:send_recv).with(request)
      file.send_recv_read
    end

    it 'parses the response as a SMB2 ReadResponse packet' do
      expect(RubySMB::SMB2::Packet::ReadResponse).to receive(:read).with(raw_response)
      file.send_recv_read
    end

    it 'raises an InvalidPacket exception if the response is not valid' do
      allow(read_response).to receive(:valid?).and_return(false)
      expect { file.send_recv_read }.to raise_error(RubySMB::Error::InvalidPacket)
    end

    context 'when the response status code is STATUS_PENDING' do
      before :example do
        allow(file).to receive(:sleep)
        allow(read_response).to receive(:status_code).and_return(WindowsError::NTStatus::STATUS_PENDING)
        allow(dispatcher).to receive(:recv_packet).and_return(raw_response)
      end

      it 'wait 1 second and calls Client dispatcher #recv_packet method one more time' do
        expect(file).to receive(:sleep).with(1)
        expect(dispatcher).to receive(:recv_packet)
        file.send_recv_read
      end

      it 'parses the response as a SMB2 ReadResponse packet' do
        expect(RubySMB::SMB2::Packet::ReadResponse).to receive(:read).twice.with(raw_response)
        file.send_recv_read
      end

      it 'raises an InvalidPacket exception if the response is not valid' do
        allow(dispatcher).to receive(:recv_packet) do
          allow(read_response).to receive(:valid?).and_return(false)
          raw_response
        end
        expect { file.send_recv_read }.to raise_error(RubySMB::Error::InvalidPacket)
      end
    end

    it 'raises an UnexpectedStatusCode exception if the response status code is not STATUS_SUCCESS' do
      allow(read_response).to receive(:status_code).and_return(WindowsError::NTStatus::STATUS_OBJECT_NAME_NOT_FOUND)
      expect { file.send_recv_read }.to raise_error(RubySMB::Error::UnexpectedStatusCode)
    end

    it 'returns the expected string' do
      expect(file.send_recv_read).to eq(read_data)
    end
  end

  describe '#send_recv_write' do
    let(:write_data) { 'write data' }
    let(:request) { double('Request') }
    let(:raw_response) { double('fake raw response data') }
    let(:write_response) {
      res = RubySMB::SMB2::Packet::WriteResponse.new
      res.write_count = write_data.size
      res
    }

    before :example do
      allow(file).to receive(:write_packet).and_return(request)
      allow(client).to receive(:send_recv).and_return(raw_response)
      allow(RubySMB::SMB2::Packet::WriteResponse).to receive(:read).with(raw_response).and_return(write_response)
    end

    it 'reads 0 bytes from offset 0 by default' do
      expect(file).to receive(:write_packet).with(data: '', offset: 0).once.and_call_original
      file.send_recv_write
    end

    it 'writes the data provided as argument' do
      expect(file).to receive(:write_packet).with(data: write_data, offset: 0).once.and_call_original
      file.send_recv_write(data: write_data)
    end

    it 'reads from the offset provided as argument' do
      offset = 3
      expect(file).to receive(:write_packet).with(data: '', offset: offset).once.and_call_original
      file.send_recv_write(offset: offset)
    end

    it 'calls Client #send_recv with the expected request' do
      expect(client).to receive(:send_recv).with(request)
      file.send_recv_write
    end

    it 'parses the response as a SMB1 WriteResponse packet' do
      expect(RubySMB::SMB2::Packet::WriteResponse).to receive(:read).with(raw_response)
      file.send_recv_write
    end

    context 'when the response status code is STATUS_PENDING' do
      before :example do
        allow(file).to receive(:sleep)
        allow(write_response).to receive(:status_code).and_return(WindowsError::NTStatus::STATUS_PENDING)
        allow(dispatcher).to receive(:recv_packet).and_return(raw_response)
      end

      it 'wait 1 second and calls Client dispatcher #recv_packet method one more time' do
        expect(file).to receive(:sleep).with(1)
        expect(dispatcher).to receive(:recv_packet)
        file.send_recv_write
      end

      it 'parses the response as a SMB2 WriteResponse packet' do
        expect(RubySMB::SMB2::Packet::WriteResponse).to receive(:read).twice.with(raw_response)
        file.send_recv_write
      end

      it 'raises an InvalidPacket exception if the response is not valid' do
        allow(dispatcher).to receive(:recv_packet) do
          allow(write_response).to receive(:valid?).and_return(false)
          raw_response
        end
        expect { file.send_recv_write }.to raise_error(RubySMB::Error::InvalidPacket)
      end
    end

    it 'raises an InvalidPacket exception if the response is not valid' do
      allow(write_response).to receive(:valid?).and_return(false)
      expect { file.send_recv_write }.to raise_error(RubySMB::Error::InvalidPacket)
    end

    it 'returns the expected response #write_count value' do
      expect(file.send_recv_write).to eq(write_data.size)
    end
  end
end

