require 'spec_helper'

RSpec.describe RubySMB::SMB2::Tree do
  let(:sock) { double('Socket', peeraddr: '192.168.1.5') }
  let(:dispatcher) { RubySMB::Dispatcher::Socket.new(sock) }

  let(:client) { RubySMB::Client.new(dispatcher, username: 'msfadmin', password: 'msfadmin') }
  let(:tree_id) { 2049 }
  let(:path) { '\\192.168.1.1\example' }
  let(:response) {
    packet = RubySMB::SMB2::Packet::TreeConnectResponse.new
    packet.smb2_header.tree_id = tree_id
    packet.maximal_access.read("\xff\x01\x1f\x00")
    packet.share_type = 0x01
    packet
  }

  let(:disco_req) { RubySMB::SMB2::Packet::TreeDisconnectRequest.new }
  let(:disco_resp) { RubySMB::SMB2::Packet::TreeDisconnectResponse.new }

  subject(:tree) {
    described_class.new(client: client, share: path, response: response)
  }

  it { is_expected.to respond_to :client }
  it { is_expected.to respond_to :permissions }
  it { is_expected.to respond_to :share }
  it { is_expected.to respond_to :id }

  it 'inherits the client that spawned it' do
    expect(tree.client).to eq client
  end

  it 'inherits the permissions from the response packet' do
    expect(tree.permissions).to eq response.maximal_access
  end

  it 'inherits the Tree id from the response packet' do
    expect(tree.id).to eq response.smb2_header.tree_id
  end

  describe '#disconnect!' do
    it 'sends a TreeDisconnectRequest with the Tree ID in the header' do
      allow(RubySMB::SMB2::Packet::TreeDisconnectRequest).to receive(:new).and_return(disco_req)
      modified_req = disco_req
      modified_req.smb2_header.tree_id = tree.id
      expect(client).to receive(:send_recv).with(modified_req).and_return(disco_resp.to_binary_s)
      tree.disconnect!
    end

    it 'raises an InvalidPacket exception if the response is not valid' do
      allow(client).to receive(:send_recv)
      allow(RubySMB::SMB2::Packet::TreeDisconnectResponse).to receive(:read).and_return(disco_resp)
      allow(disco_resp).to receive(:valid?).and_return(false)
      expect { tree.disconnect! }.to raise_error(RubySMB::Error::InvalidPacket)
    end

    it 'returns the NTStatus code from the response' do
      allow(client).to receive(:send_recv).and_return(disco_resp.to_binary_s)
      expect(tree.disconnect!).to eq disco_resp.status_code
    end
  end

  describe '#set_header_fields' do
    let(:modified_request) { tree.set_header_fields(disco_req) }
    it 'adds the TreeID to the header' do
      expect(modified_request.smb2_header.tree_id).to eq tree.id
    end

    it 'sets the credit charge to 1' do
      expect(modified_request.smb2_header.credit_charge).to eq 1
    end

    it 'sets the credits to 256' do
      expect(modified_request.smb2_header.credits).to eq 256
    end
  end

  describe '#open_directory_packet' do
    describe 'directory name' do
      it 'uses a null byte of nothing is passed in' do
        expect(tree.open_directory_packet.name).to eq "\x00".encode('UTF-16LE')
      end

      it 'sets the #name_length to 0 if no name is passed in' do
        expect(tree.open_directory_packet.name_length).to eq 0
      end

      it 'encodes any supplied file name in UTF-16LE' do
        name = 'hello.txt'
        expect(tree.open_directory_packet(directory: name).name).to eq name.encode('UTF-16LE')
      end
    end

    describe 'disposition' do
      it 'defaults to FILE_OPEN' do
        expect(tree.open_directory_packet.create_disposition).to eq RubySMB::Dispositions::FILE_OPEN
      end

      it 'can take the Disposition as an argument' do
        expect(tree.open_directory_packet(disposition: RubySMB::Dispositions::FILE_OPEN_IF).create_disposition).to eq RubySMB::Dispositions::FILE_OPEN_IF
      end
    end

    describe 'impersonation level' do
      it 'defaults to SEC_IMPERSONATE' do
        expect(tree.open_directory_packet.impersonation_level).to eq RubySMB::ImpersonationLevels::SEC_IMPERSONATE
      end

      it 'can take the Impersonation Level as an argument' do
        expect(tree.open_directory_packet(impersonation: RubySMB::ImpersonationLevels::SEC_DELEGATE).impersonation_level).to eq RubySMB::ImpersonationLevels::SEC_DELEGATE
      end
    end

    describe 'RWD access permissions' do
      it 'will set the read permission from the parameters' do
        expect(tree.open_directory_packet(read: true).share_access.read_access).to eq 1
      end

      it 'will set the write permission from the parameters' do
        expect(tree.open_directory_packet(write: true).share_access.write_access).to eq 1
      end

      it 'will set the delete permission from the parameters' do
        expect(tree.open_directory_packet(delete: true).share_access.delete_access).to eq 1
      end
    end
  end

  describe '#open_directory' do
    let(:create_req) { RubySMB::SMB2::Packet::CreateRequest.new }
    let(:create_response) { RubySMB::SMB2::Packet::CreateResponse.new }

    it 'sends the create request packet and gets a response back' do
      allow(tree).to receive(:open_directory_packet).and_return(create_req)
      expect(client).to receive(:send_recv).with(create_req).and_return(create_response.to_binary_s)
      tree.open_directory
    end

    context 'when the response is not a valid packet' do
      it 'raises an InvalidPacket exception' do
        allow(client).to receive(:send_recv)
        allow(RubySMB::SMB2::Packet::CreateResponse).to receive(:read).and_return(create_response)
        create_response.smb2_header.command = RubySMB::SMB2::Commands::LOGOFF
        expect { tree.open_directory }.to raise_error(RubySMB::Error::InvalidPacket)
      end
    end
  end

  describe '#list' do
    let(:create_res) { double('create response') }
    let(:query_dir_req) { RubySMB::SMB2::Packet::QueryDirectoryRequest.new }
    let(:query_dir_res) { RubySMB::SMB2::Packet::QueryDirectoryResponse.new }

    before :example do
      allow(tree).to receive(:open_directory).and_return(create_res)
      allow(create_res).to receive(:file_id)
      allow(RubySMB::SMB2::Packet::QueryDirectoryRequest).to receive(:new).and_return(query_dir_req)
      allow(client).to receive(:send_recv)
      allow(RubySMB::SMB2::Packet::QueryDirectoryResponse).to receive(:read).and_return(query_dir_res)
      query_dir_res.smb2_header.nt_status = WindowsError::NTStatus::STATUS_NO_MORE_FILES.value
    end

    it 'calls #open_directory' do
      dir = '/dir'
      expect(tree).to receive(:open_directory).with(directory: dir).and_return(create_res)
      tree.list(directory: dir)
    end

    it 'uses the File ID from the create response' do
      file_id = RubySMB::Field::Smb2Fileid.new
      allow(create_res).to receive(:file_id).and_return(file_id)
      allow(client).to receive(:send_recv) do |packet|
        expect(packet.file_id).to eq file_id
      end
      tree.list
    end

    it 'sets the default QueryDirectoryRequest values' do
      allow(client).to receive(:send_recv) do |packet|
        expect(packet.file_information_class).to eq RubySMB::Fscc::FileInformation::FileIdFullDirectoryInformation::CLASS_LEVEL
        expect(packet.name).to eq '*'.encode('UTF-16LE')
        expect(packet.output_length).to eq 65_535
      end
      tree.list
    end

    it 'sets QueryDirectoryRequest #name field to the pattern passed as argument' do
      pattern = '/dir/*/'.encode('UTF-16LE')
      allow(client).to receive(:send_recv) do |packet|
        expect(packet.name).to eq pattern
      end
      tree.list(pattern: pattern)
    end

    it 'sets QueryDirectoryRequest #file_information_class field to the type passed as argument' do
      type = RubySMB::Fscc::FileInformation::FileDirectoryInformation
      allow(client).to receive(:send_recv) do |packet|
        expect(packet.file_information_class).to eq type::CLASS_LEVEL
      end
      tree.list(type: type)
    end

    it 'calls #set_header_fields' do
      expect(tree).to receive(:set_header_fields).with(query_dir_req).and_call_original
      tree.list
    end

    let(:file1) { double('file information') }
    let(:file2) { double('file information') }

    it 'returns the expected file information' do
      query_dir_res.smb2_header.nt_status = WindowsError::NTStatus::STATUS_SUCCESS.value
      allow(query_dir_res).to receive(:results) do |_type|
        query_dir_res.smb2_header.nt_status = WindowsError::NTStatus::STATUS_NO_MORE_FILES.value
        [file1]
      end
      expect(tree.list).to eq([file1])
    end

    context 'when the response is not a valid packet' do
      it 'raises an InvalidPacket exception' do
        query_dir_res.smb2_header.command = RubySMB::SMB2::Commands::LOGOFF
        expect { tree.list }.to raise_error(RubySMB::Error::InvalidPacket)
      end
    end

    context 'when multiple requests are needed to retrieve the full directory list' do
      before :example do
        query_dir_res.smb2_header.nt_status = WindowsError::NTStatus::STATUS_SUCCESS.value
        first_query = true
        allow(query_dir_res).to receive(:results) do |_type|
          if first_query
            first_query = false
            [file1]
          else
            query_dir_res.smb2_header.nt_status = WindowsError::NTStatus::STATUS_NO_MORE_FILES.value
            [file2]
          end
        end
      end

      it 'returns the expected file information' do
        expect(tree.list).to eq([file1] + [file2])
      end

      it 'resets the message ID between the requests' do
        allow(client).to receive(:send_recv) do |packet|
          expect(packet.smb2_header.message_id).to eq 0
          packet.smb2_header.message_id = 1
        end
        tree.list
      end
    end

    context 'when an unexpected status code is received' do
      it 'raises an exception' do
        query_dir_res.smb2_header.nt_status = WindowsError::NTStatus::STATUS_FILE_NOT_AVAILABLE.value
        expect { tree.list }.to raise_error(RubySMB::Error::UnexpectedStatusCode)
      end
    end

  end

  describe '#open_file' do
    let(:create_request)      { RubySMB::SMB2::Packet::CreateRequest.new }
    let(:create_response) { RubySMB::SMB2::Packet::CreateResponse.new }
    let(:filename) { "test_file\x00".encode('UTF-16LE') }

    before :each do
      allow(RubySMB::SMB2::Packet::CreateRequest).to receive(:new).and_return(create_request)
      allow(RubySMB::SMB2::Packet::CreateResponse).to receive(:read).and_return(create_response)
    end

    it 'calls #set_header_fields' do
      allow(client).to receive(:send_recv).and_return(create_response.to_binary_s)
      expect(tree).to receive(:set_header_fields).with(create_request).and_call_original
      tree.open_file(filename: filename)
    end

    describe 'filename' do
      it 'takes the filename as an argument' do
        allow(client).to receive(:send_recv) do |packet|
          expect(packet.name).to eq(filename)
          create_response.to_binary_s
        end
        tree.open_file(filename: filename)
      end
    end

    describe 'attributes' do
      it 'has the correct default fields set' do
        allow(client).to receive(:send_recv) do |packet|
          expect(packet.file_attributes.directory).to eq(0)
          expect(packet.file_attributes.normal).to eq(1)
          create_response.to_binary_s
        end
        tree.open_file(filename: filename)
      end

      it 'can take the Attributes as an argument' do
        attributes = { normal: 0 }
        allow(client).to receive(:send_recv) do |packet|
          expect(packet.file_attributes.normal).to eq(0)
          create_response.to_binary_s
        end
        tree.open_file(filename: filename, attributes: attributes)
      end
    end

    describe 'options' do
      it 'has the correct default fields set' do
        allow(client).to receive(:send_recv) do |packet|
          expect(packet.create_options.directory_file).to eq(0)
          expect(packet.create_options.non_directory_file).to eq(1)
          create_response.to_binary_s
        end
        tree.open_file(filename: filename)
      end

      it 'can take the Create Options as an argument' do
        options = RubySMB::SMB1::BitField::CreateOptions.new(directory_file: 1)
        allow(client).to receive(:send_recv) do |packet|
          expect(packet.create_options.directory_file).to eq(1)
          expect(packet.create_options.non_directory_file).to eq(0)
          create_response.to_binary_s
        end
        tree.open_file(filename: filename, options: options)
      end
    end

    describe 'disposition' do
      it 'defaults to FILE_OPEN' do
        allow(client).to receive(:send_recv) do |packet|
          expect(packet.create_disposition).to eq(RubySMB::Dispositions::FILE_OPEN)
          create_response.to_binary_s
        end
        tree.open_file(filename: filename)
      end

      it 'can take the Disposition as an argument' do
        allow(client).to receive(:send_recv) do |packet|
          expect(packet.create_disposition).to eq(RubySMB::Dispositions::FILE_OPEN_IF)
          create_response.to_binary_s
        end
        tree.open_file(filename: filename, disposition: RubySMB::Dispositions::FILE_OPEN_IF)
      end
    end

    describe 'impersonation level' do
      it 'defaults to SEC_IMPERSONATE' do
        allow(client).to receive(:send_recv) do |packet|
          expect(packet.impersonation_level).to eq(RubySMB::ImpersonationLevels::SEC_IMPERSONATE)
          create_response.to_binary_s
        end
        tree.open_file(filename: filename)
      end

      it 'can take the Impersonation Level as an argument' do
        allow(client).to receive(:send_recv) do |packet|
          expect(packet.impersonation_level).to eq(RubySMB::ImpersonationLevels::SEC_DELEGATE)
          create_response.to_binary_s
        end
        tree.open_file(filename: filename, impersonation: RubySMB::ImpersonationLevels::SEC_DELEGATE)
      end
    end

    describe 'RWD access permissions' do
      it 'will set the read permission from the parameters' do
        allow(client).to receive(:send_recv) do |packet|
          expect(packet.share_access.read_access).to    eq(1)
          expect(packet.desired_access.read_data).to    eq(1)
          create_response.to_binary_s
        end
        tree.open_file(filename: filename, read: true)
      end

      it 'will set the write permission from the parameters' do
        allow(client).to receive(:send_recv) do |packet|
          expect(packet.share_access.write_access).to   eq(1)
          expect(packet.desired_access.write_data).to  eq(1)
          expect(packet.desired_access.append_data).to eq(1)
          create_response.to_binary_s
        end
        tree.open_file(filename: filename, write: true)
      end

      it 'will set the delete permission from the parameters' do
        allow(client).to receive(:send_recv) do |packet|
          expect(packet.share_access.delete_access).to    eq(1)
          expect(packet.desired_access.delete_access).to eq(1)
          create_response.to_binary_s
        end
        tree.open_file(filename: filename, delete: true)
      end
    end

    it 'sets #requested_oplock to 0xFF' do
      allow(client).to receive(:send_recv) do |packet|
        expect(packet.requested_oplock).to eq(0xFF)
        create_response.to_binary_s
      end
      tree.open_file(filename: filename, delete: true)
    end

    it 'sends the CreateRequest request packet and gets the expected CreateResponse response back' do
      expect(client).to receive(:send_recv).with(create_request).and_return(create_response.to_binary_s)
      tree.open_file(filename: filename)
    end

    context 'when sending the request packet and gets a response back' do
      before :example do
        allow(client).to receive(:send_recv).with(create_request).and_return(create_response.to_binary_s)
      end

      context 'when it is a file' do
        it 'returns the expected RubySMB::SMB2::File object' do
          file_obj = RubySMB::SMB2::File.new(name: filename, tree: tree, response: create_response)
          expect(RubySMB::SMB2::File).to receive(:new).with(name: filename, tree: tree, response: create_response).and_return(file_obj)
          expect(tree.open_file(filename: filename)).to eq(file_obj)
        end
      end

      context 'when it is a pipe' do
        it 'returns the expected RubySMB::SMB2::Pipe object' do
          response.share_type = 0x02
          pipe_obj = RubySMB::SMB2::Pipe.new(name: filename, tree: tree, response: create_response)
          expect(RubySMB::SMB2::Pipe).to receive(:new).with(name: filename, tree: tree, response: create_response).and_return(pipe_obj)
          expect(tree.open_file(filename: filename)).to eq(pipe_obj)
        end
      end

      context 'when it is an unsupported share type' do
        it 'raises a RubySMBError exception' do
          response.share_type = 0x03
          expect { tree.open_file(filename: filename) }.to raise_error(RubySMB::Error::RubySMBError)
        end
      end

      context 'when the response is not a CreateResponse packet' do
        it 'raises an InvalidPacket exception' do
          create_response.smb2_header.command = RubySMB::SMB2::Commands::LOGOFF
          expect { tree.open_file(filename: filename) }.to raise_error(RubySMB::Error::InvalidPacket)
        end
      end

      context 'when the response status code is not STATUS_SUCCESS' do
        it 'raises an UnexpectedStatusCode exception' do
          create_response.smb2_header.nt_status = WindowsError::NTStatus::STATUS_INVALID_HANDLE.value
          expect { tree.open_file(filename: filename) }.to raise_error(RubySMB::Error::UnexpectedStatusCode)
        end
      end
    end
  end
end
