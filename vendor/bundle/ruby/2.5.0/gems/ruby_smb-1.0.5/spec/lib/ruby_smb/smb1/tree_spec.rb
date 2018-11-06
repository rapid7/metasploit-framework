require 'spec_helper'

RSpec.describe RubySMB::SMB1::Tree do
  let(:ip) { '1.2.3.4' }
  let(:sock) { double('Socket', peeraddr: ip) }
  let(:dispatcher) { RubySMB::Dispatcher::Socket.new(sock) }

  let(:client) { RubySMB::Client.new(dispatcher, username: 'msfadmin', password: 'msfadmin') }
  let(:tree_id) { 2050 }
  let(:path) { "\\\\#{ip}\\example" }
  let(:response) {
    packet = RubySMB::SMB1::Packet::TreeConnectResponse.new
    packet.smb_header.tid = tree_id
    packet.parameter_block.access_rights.read("\xff\x01\x1f\x00")
    packet.parameter_block.guest_access_rights.read("\xff\x01\x1f\x01")
    packet
  }

  let(:disco_req) { RubySMB::SMB1::Packet::TreeDisconnectRequest.new }
  let(:disco_resp) { RubySMB::SMB1::Packet::TreeDisconnectResponse.new }

  subject(:tree) {
    described_class.new(client: client, share: path, response: response)
  }

  it { is_expected.to respond_to :client }
  it { is_expected.to respond_to :guest_permissions }
  it { is_expected.to respond_to :permissions }
  it { is_expected.to respond_to :share }
  it { is_expected.to respond_to :id }

  it 'inherits the client that spawned it' do
    expect(tree.client).to eq client
  end

  it 'inherits the guest permissions from the response packet' do
    expect(tree.guest_permissions).to eq response.parameter_block.guest_access_rights
  end

  it 'inherits the permissions from the response packet' do
    expect(tree.permissions).to eq response.parameter_block.access_rights
  end

  it 'inherits the Tree id from the response packet' do
    expect(tree.id).to eq response.smb_header.tid
  end

  describe '#disconnect!' do
    let(:disco_response) { double('Response') }

    before :example do
      allow(RubySMB::SMB1::Packet::TreeDisconnectRequest).to receive(:new).and_return(disco_req)
      allow(RubySMB::SMB1::Packet::TreeDisconnectResponse).to receive(:read).and_return(disco_resp)
      allow(client).to receive(:send_recv)
    end

    it 'calls #set_header_fields' do
      expect(tree).to receive(:set_header_fields).with(disco_req)
      tree.disconnect!
    end

    it 'sends a TreeDisconnectRequest with the Tree ID in the header' do
      modified_req = disco_req
      modified_req.smb_header.tid = tree.id
      expect(client).to receive(:send_recv).with(modified_req)
      tree.disconnect!
    end

    it 'returns the NTStatus code from the response' do
      expect(tree.disconnect!).to eq disco_resp.status_code
    end

    it 'raises an InvalidPacket exception if the response is not valid' do
      allow(disco_resp).to receive(:valid?).and_return(false)
      expect { tree.disconnect! }.to raise_error(RubySMB::Error::InvalidPacket)
    end
  end

  describe '#open_file' do
    let(:nt_create_andx_req)      { RubySMB::SMB1::Packet::NtCreateAndxRequest.new }
    let(:nt_create_andx_response) { RubySMB::SMB1::Packet::NtCreateAndxResponse.new }
    let(:filename) { "test_file\x00" }

    before :each do
      allow(RubySMB::SMB1::Packet::NtCreateAndxRequest).to receive(:new).and_return(nt_create_andx_req)
      allow(RubySMB::SMB1::Packet::NtCreateAndxResponse).to receive(:read).and_return(nt_create_andx_response)
    end

    it 'calls #set_header_fields' do
      allow(client).to receive(:send_recv).and_return(nt_create_andx_response.to_binary_s)
      expect(tree).to receive(:set_header_fields).with(nt_create_andx_req).and_call_original
      tree.open_file(filename: filename)
    end

    describe 'filename' do
      it 'takes the filename as an argument' do
        allow(client).to receive(:send_recv) do |packet|
          expect(packet.data_block.file_name).to eq(filename)
          nt_create_andx_response.to_binary_s
        end
        tree.open_file(filename: filename)
      end

      it 'adds the null termination to the filename if missing' do
        allow(client).to receive(:send_recv) do |packet|
          expect(packet.data_block.file_name).to eq(filename)
          nt_create_andx_response.to_binary_s
        end
        tree.open_file(filename: filename.chop)
      end

      it 'adds the unicode null termination to the filename if Unicode is enabled' do
        unicode_filename = filename.encode('UTF-16LE')
        nt_create_andx_req.smb_header.flags2.unicode = 1
        allow(client).to receive(:send_recv) do |packet|
          expect(packet.data_block.file_name).to eq(unicode_filename.b)
          nt_create_andx_response.to_binary_s
        end
        tree.open_file(filename: unicode_filename.chop)
      end
    end

    describe 'flags' do
      it 'has the correct default fields set' do
        allow(client).to receive(:send_recv) do |packet|
          expect(packet.parameter_block.flags.request_extended_response).to eq(1)
          nt_create_andx_response.to_binary_s
        end
        tree.open_file(filename: filename)
      end

      it 'can take the Flags as an argument' do
        flags = { request_extended_response: 0 }
        allow(client).to receive(:send_recv) do |packet|
          expect(packet.parameter_block.flags.request_extended_response).to eq(0)
          nt_create_andx_response.to_binary_s
        end
        tree.open_file(filename: filename, flags: flags)
      end
    end

    describe 'options' do
      it 'has the correct default fields set' do
        allow(client).to receive(:send_recv) do |packet|
          expect(packet.parameter_block.create_options.directory_file).to eq(0)
          expect(packet.parameter_block.create_options.non_directory_file).to eq(1)
          nt_create_andx_response.to_binary_s
        end
        tree.open_file(filename: filename)
      end

      it 'can take the Flags as an argument' do
        options = RubySMB::SMB1::BitField::CreateOptions.new(directory_file: 1)
        allow(client).to receive(:send_recv) do |packet|
          expect(packet.parameter_block.create_options.directory_file).to eq(1)
          expect(packet.parameter_block.create_options.non_directory_file).to eq(0)
          nt_create_andx_response.to_binary_s
        end
        tree.open_file(filename: filename, options: options)
      end
    end

    describe 'disposition' do
      it 'defaults to FILE_OPEN' do
        allow(client).to receive(:send_recv) do |packet|
          expect(packet.parameter_block.create_disposition).to eq(RubySMB::Dispositions::FILE_OPEN)
          nt_create_andx_response.to_binary_s
        end
        tree.open_file(filename: filename)
      end

      it 'can take the Disposition as an argument' do
        allow(client).to receive(:send_recv) do |packet|
          expect(packet.parameter_block.create_disposition).to eq(RubySMB::Dispositions::FILE_OPEN_IF)
          nt_create_andx_response.to_binary_s
        end
        tree.open_file(filename: filename, disposition: RubySMB::Dispositions::FILE_OPEN_IF)
      end
    end

    describe 'impersonation level' do
      it 'defaults to SEC_IMPERSONATE' do
        allow(client).to receive(:send_recv) do |packet|
          expect(packet.parameter_block.impersonation_level).to eq(RubySMB::ImpersonationLevels::SEC_IMPERSONATE)
          nt_create_andx_response.to_binary_s
        end
        tree.open_file(filename: filename)
      end

      it 'can take the Impersonation Level as an argument' do
        allow(client).to receive(:send_recv) do |packet|
          expect(packet.parameter_block.impersonation_level).to eq(RubySMB::ImpersonationLevels::SEC_DELEGATE)
          nt_create_andx_response.to_binary_s
        end
        tree.open_file(filename: filename, impersonation: RubySMB::ImpersonationLevels::SEC_DELEGATE)
      end
    end

    describe 'RWD access permissions' do
      it 'will set the read permission from the parameters' do
        allow(client).to receive(:send_recv) do |packet|
          expect(packet.parameter_block.share_access.share_read).to     eq(1)
          expect(packet.parameter_block.desired_access.read_data).to    eq(1)
          expect(packet.parameter_block.desired_access.read_ea).to      eq(1)
          expect(packet.parameter_block.desired_access.read_attr).to    eq(1)
          expect(packet.parameter_block.desired_access.read_control).to eq(1)
          nt_create_andx_response.to_binary_s
        end
        tree.open_file(filename: filename, read: true)
      end

      it 'will set the write permission from the parameters' do
        allow(client).to receive(:send_recv) do |packet|
          expect(packet.parameter_block.share_access.share_write).to   eq(1)
          expect(packet.parameter_block.desired_access.write_data).to  eq(1)
          expect(packet.parameter_block.desired_access.append_data).to eq(1)
          expect(packet.parameter_block.desired_access.write_ea).to    eq(1)
          expect(packet.parameter_block.desired_access.write_attr).to  eq(1)
          nt_create_andx_response.to_binary_s
        end
        tree.open_file(filename: filename, write: true)
      end

      it 'will set the delete permission from the parameters' do
        allow(client).to receive(:send_recv) do |packet|
          expect(packet.parameter_block.share_access.share_delete).to    eq(1)
          expect(packet.parameter_block.desired_access.delete_access).to eq(1)
          nt_create_andx_response.to_binary_s
        end
        tree.open_file(filename: filename, delete: true)
      end
    end

    it 'sends the NtCreateAndxRequest request packet and gets the expected NtCreateAndxResponse response back' do
      expect(client).to receive(:send_recv).with(nt_create_andx_req).and_return(nt_create_andx_response.to_binary_s)
      tree.open_file(filename: filename)
    end

    context 'when sending the request packet and gets a response back' do
      before :example do
        allow(client).to receive(:send_recv).with(nt_create_andx_req).and_return(nt_create_andx_response.to_binary_s)
      end

      it 'returns the expected RubySMB::SMB1::File object' do
        file_obj = RubySMB::SMB1::File.new(name: filename, tree: tree, response: nt_create_andx_response)
        expect(RubySMB::SMB1::File).to receive(:new).with(name: filename, tree: tree, response: nt_create_andx_response).and_return(file_obj)
        expect(tree.open_file(filename: filename)).to eq(file_obj)
      end

      context 'when the response is not a NtCreateAndxResponse packet' do
        it 'raises an InvalidPacket exception' do
          nt_create_andx_response.smb_header.command = RubySMB::SMB1::Commands::SMB_COM_ECHO
          expect { tree.open_file(filename: filename) }.to raise_error(RubySMB::Error::InvalidPacket)
        end
      end

      context 'when the response status code is not STATUS_SUCCESS' do
        it 'raises an UnexpectedStatusCode exception' do
          nt_create_andx_response.smb_header.nt_status = WindowsError::NTStatus::STATUS_INVALID_HANDLE.value
          expect { tree.open_file(filename: filename) }.to raise_error(RubySMB::Error::UnexpectedStatusCode)
        end
      end
    end
  end

  describe '#list' do
    let(:find_first2_req) { RubySMB::SMB1::Packet::Trans2::FindFirst2Request.new }
    let(:file_info1) do
      file_info = RubySMB::SMB1::Packet::Trans2::FindInformationLevel::FindFileFullDirectoryInfo.new
      file_info.unicode = true
      file_info.file_name = 'test1.txt'
      file_info
    end
    let(:find_first2_res) do
      packet = RubySMB::SMB1::Packet::Trans2::FindFirst2Response.new
      packet.data_block.trans2_parameters.eos = 1
      packet.data_block.trans2_data.buffer = file_info1.to_binary_s
      packet
    end

    before :each do
      allow(RubySMB::SMB1::Packet::Trans2::FindFirst2Request).to receive(:new).and_return(find_first2_req)
      allow(client).to receive(:send_recv)
      allow(RubySMB::SMB1::Packet::Trans2::FindFirst2Response).to receive(:read).and_return(find_first2_res)
    end

    it 'calls #set_header_fields' do
      expect(tree).to receive(:set_header_fields).with(find_first2_req).and_call_original
      tree.list
    end

    it 'sets the unicode flag when the unicode argument is true (default)' do
      allow(client).to receive(:send_recv).with(find_first2_req) do |packet|
        expect(packet.smb_header.flags2.unicode).to eq 1
      end
      tree.list
    end

    it 'does not set the unicode flag when the unicode argument is false' do
      allow(client).to receive(:send_recv).with(find_first2_req) do |packet|
        expect(packet.smb_header.flags2.unicode).to eq 0
      end
      tree.list(unicode: false)
    end

    it 'adds a leading and trailing \\ to the search path if not present' do
      directory = 'dir'
      search = ('\\' + directory + '\\*').encode('UTF-16LE')
      allow(client).to receive(:send_recv).with(find_first2_req) do |packet|
        expect(packet.data_block.trans2_parameters.filename).to eq search
      end
      tree.list(directory: directory)
    end

    it 'sets the expected default search parameters' do
      allow(client).to receive(:send_recv).with(find_first2_req) do |packet|
        t2_params = packet.data_block.trans2_parameters
        expect(t2_params.search_attributes.hidden).to eq 1
        expect(t2_params.search_attributes.system).to eq 1
        expect(t2_params.search_attributes.directory).to eq 1
        expect(t2_params.flags.close_eos).to eq 1
        expect(t2_params.flags.resume_keys).to eq 0
        expect(t2_params.information_level).to eq RubySMB::SMB1::Packet::Trans2::FindInformationLevel::FindFileFullDirectoryInfo::CLASS_LEVEL
        expect(t2_params.filename).to eq '\\*'.encode('UTF-16LE')
        expect(t2_params.search_count).to eq 10
      end
      tree.list
    end

    it 'calls #set_find_params' do
      expect(tree).to receive(:set_find_params).with(find_first2_req).and_call_original
      tree.list
    end

    it 'calls FindFileFullDirectoryInfo#results' do
      expect(find_first2_res).to receive(:results).with(RubySMB::SMB1::Packet::Trans2::FindInformationLevel::FindFileFullDirectoryInfo, unicode: true).and_call_original
      tree.list
    end

    it 'returns the expected FindFileFullDirectoryInfo structure' do
      expect(tree.list).to eq([file_info1])
    end

    it 'returns the expected FindFileFullDirectoryInfo structures when multiple files are listed' do
      file_info1.next_offset = file_info1.do_num_bytes
      file_info2 = RubySMB::SMB1::Packet::Trans2::FindInformationLevel::FindFileFullDirectoryInfo.new
      file_info2.unicode = true
      file_info2.file_name = 'test2.txt'
      find_first2_res.data_block.trans2_data.buffer = file_info1.to_binary_s + file_info2.to_binary_s

      expect(tree.list).to eq([file_info1, file_info2])
    end

    context 'when the response is not a valid Trans2 FindFirst2Response' do
      it 'raises an InvalidPacket exception' do
        find_first2_res.smb_header.command = RubySMB::SMB1::Commands::SMB_COM_ECHO
        expect { tree.list }.to raise_error(RubySMB::Error::InvalidPacket)
      end
    end

    context 'when the response status code is not STATUS_SUCCESS' do
      it 'raises an UnexpectedStatusCode exception' do
        find_first2_res.smb_header.nt_status = WindowsError::NTStatus::STATUS_INVALID_HANDLE.value
        expect { tree.list }.to raise_error(RubySMB::Error::UnexpectedStatusCode)
      end
    end

    context 'when more requests are needed to get all the information' do
      let(:find_next2_req) { RubySMB::SMB1::Packet::Trans2::FindNext2Request.new }
      let(:file_info2) do
        file_info = RubySMB::SMB1::Packet::Trans2::FindInformationLevel::FindFileFullDirectoryInfo.new
        file_info.unicode = true
        file_info.file_name = 'test2.txt'
        file_info
      end
      let(:find_next2_res) do
        packet = RubySMB::SMB1::Packet::Trans2::FindNext2Response.new
        packet.data_block.trans2_parameters.eos = 1
        packet.data_block.trans2_data.buffer = file_info2.to_binary_s
        packet
      end
      let(:sid) { 0x1000 }

      before :each do
        find_first2_res.data_block.trans2_parameters.eos = 0
        find_first2_res.data_block.trans2_parameters.sid = sid
        allow(RubySMB::SMB1::Packet::Trans2::FindNext2Request).to receive(:new).and_return(find_next2_req)
        allow(client).to receive(:send_recv).with(find_next2_req)
        allow(RubySMB::SMB1::Packet::Trans2::FindNext2Response).to receive(:read).and_return(find_next2_res)
      end

      it 'calls #set_header_fields' do
        expect(tree).to receive(:set_header_fields).with(find_first2_req).once.ordered.and_call_original
        expect(tree).to receive(:set_header_fields).with(find_next2_req).once.ordered.and_call_original
        tree.list
      end

      it 'sets the unicode flag when the unicode argument is true (default)' do
        allow(client).to receive(:send_recv).with(find_next2_req) do |packet|
          expect(packet.smb_header.flags2.unicode).to eq 1
        end
        tree.list
      end

      it 'does not set the unicode flag when the unicode argument is false' do
        allow(client).to receive(:send_recv).with(find_next2_req) do |packet|
          expect(packet.smb_header.flags2.unicode).to eq 0
        end
        tree.list(unicode: false)
      end

      it 'sets the expected default search parameters' do
        allow(client).to receive(:send_recv).with(find_next2_req) do |packet|
          t2_params = packet.data_block.trans2_parameters
          expect(t2_params.sid).to eq sid
          expect(t2_params.flags.close_eos).to eq 1
          expect(t2_params.flags.resume_keys).to eq 0
          expect(t2_params.information_level).to eq RubySMB::SMB1::Packet::Trans2::FindInformationLevel::FindFileFullDirectoryInfo::CLASS_LEVEL
          expect(t2_params.filename).to eq file_info1.file_name
          expect(t2_params.search_count).to eq 10
        end
        tree.list
      end

      it 'calls #set_find_params' do
        expect(tree).to receive(:set_find_params).with(find_first2_req).once.ordered.and_call_original
        expect(tree).to receive(:set_find_params).with(find_next2_req).once.ordered.and_call_original
        tree.list
      end

      it 'calls FindFileFullDirectoryInfo#results' do
        expect(find_first2_res).to receive(:results).with(RubySMB::SMB1::Packet::Trans2::FindInformationLevel::FindFileFullDirectoryInfo, unicode: true).once.ordered.and_call_original
        expect(find_next2_res).to receive(:results).with(RubySMB::SMB1::Packet::Trans2::FindInformationLevel::FindFileFullDirectoryInfo, unicode: true).once.ordered.and_call_original
        tree.list
      end

      it 'returns the expected FindFileFullDirectoryInfo structures' do
        expect(tree.list).to eq([file_info1, file_info2])
      end

      context 'when the response is not a valid Trans2 FindNext2Response' do
        it 'raises an InvalidPacket exception' do
          find_next2_res.smb_header.command = RubySMB::SMB1::Commands::SMB_COM_ECHO
          expect { tree.list }.to raise_error(RubySMB::Error::InvalidPacket)
        end
      end

      context 'when the response status code is not STATUS_SUCCESS' do
        it 'raises an UnexpectedStatusCode exception' do
          find_next2_res.smb_header.nt_status = WindowsError::NTStatus::STATUS_INVALID_HANDLE.value
          expect { tree.list }.to raise_error(RubySMB::Error::UnexpectedStatusCode)
        end
      end
    end
  end

  describe '#set_header_fields' do
    let(:modified_request) { tree.set_header_fields(disco_req) }
    it 'adds the TreeID to the header' do
      expect(modified_request.smb_header.tid).to eq tree.id
    end

    it 'sets the Flags2 extended attributes field to 1' do
      expect(modified_request.smb_header.flags2.eas).to eq 1
    end
  end

  describe '#set_find_params' do
    let(:find_first2_req) { RubySMB::SMB1::Packet::Trans2::FindFirst2Request.new }
    let(:modified_request) { tree.send(:set_find_params, find_first2_req) }

    it 'sets #data_count to 0' do
      expect(modified_request.parameter_block.data_count).to eq 0
    end

    it 'sets #data_offset to 0' do
      expect(modified_request.parameter_block.data_offset).to eq 0
    end

    it 'sets #total_parameter_count to #parameter_count value' do
      find_first2_req.parameter_block.parameter_count = 10
      expect(modified_request.parameter_block.total_parameter_count).to eq 10
    end

    it 'sets #max_parameter_count to #parameter_count value' do
      find_first2_req.parameter_block.parameter_count = 10
      expect(modified_request.parameter_block.max_parameter_count).to eq 10
    end

    it 'sets #max_data_count to 16,384' do
      expect(modified_request.parameter_block.max_data_count).to eq 16_384
    end
  end

end
