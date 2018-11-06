RSpec.describe RubySMB::SMB2::Pipe do

  let(:sock) { double('Socket', peeraddr: '192.168.1.5') }
  let(:dispatcher) { RubySMB::Dispatcher::Socket.new(sock) }

  let(:client) { RubySMB::Client.new(dispatcher, username: 'msfadmin', password: 'msfadmin') }
  let(:tree_id) { 2049 }
  let(:path) { '\\192.168.1.1\IPC$' }
  let(:connect_response) {
    packet = RubySMB::SMB2::Packet::TreeConnectResponse.new
    packet.smb2_header.tree_id = tree_id
    packet.maximal_access.read("\xff\x01\x1f\x00")
    packet.share_type = 0x01
    packet
  }

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

  let(:ioctl_response) {
    packet = RubySMB::SMB2::Packet::IoctlResponse.new
    packet.buffer = "\x03\x00\x00\x00" + "\x10\x20\x30\x40" + "\x00\x00\x00\x00" + "\x00\x00\x00\x00"
    packet
  }

  subject(:pipe) { described_class.new(name: 'msf-pipe', response: create_response, tree: tree) }

  describe '#peek' do
    let(:request) { RubySMB::SMB2::Packet::IoctlRequest.new }
    let(:raw_response) { double('Raw response') }
    let(:response) { double('Response') }

    before :example do
      allow(RubySMB::SMB2::Packet::IoctlRequest).to receive(:new).and_return(request)
      allow(client).to receive(:send_recv).and_return(raw_response)
      allow(RubySMB::SMB2::Packet::IoctlResponse).to receive(:read).and_return(response)
      allow(response).to receive(:valid?).and_return(true)
      allow(response).to receive(:status_code).and_return(WindowsError::NTStatus::STATUS_SUCCESS)
    end

    it 'creates a IoctlRequest'do
      expect(RubySMB::SMB2::Packet::IoctlRequest).to receive(:new)
      pipe.peek
    end

    it 'sets the request #ctl_code field' do
      expect(request).to receive(:ctl_code=).with(RubySMB::Fscc::ControlCodes::FSCTL_PIPE_PEEK)
      pipe.peek
    end

    it 'sets the request #is_fsctl flag to true' do
      pipe.peek
      expect(request.flags.is_fsctl).to eq 1
    end

    it 'sets the request #max_output_response field to the expected value' do
      pipe.peek(peek_size: 10)
      expect(request.max_output_response).to eq(16 + 10)
    end

    it 'calls #set_header_fields' do
      expect(pipe).to receive(:set_header_fields).with(request)
      pipe.peek
    end

    it 'calls Client #send_recv' do
      expect(client).to receive(:send_recv).with(request)
      pipe.peek
    end

    it 'parses the response as a SMB2 IoctlResponse packet' do
      expect(RubySMB::SMB2::Packet::IoctlResponse).to receive(:read).with(raw_response)
      pipe.peek
    end

    it 'raises an InvalidPacket exception if the response is not valid' do
      allow(response).to receive(:valid?).and_return(false)
      smb2_header = double('SMB2 Header')
      allow(response).to receive(:smb2_header).and_return(smb2_header)
      allow(smb2_header).to receive_messages(:protocol => nil, :command => nil)
      expect { pipe.peek }.to raise_error(RubySMB::Error::InvalidPacket)
    end

    it 'raises an UnexpectedStatusCode exception if the response status code is not STATUS_SUCCESS or STATUS_BUFFER_OVERFLOW' do
      allow(response).to receive(:status_code).and_return(WindowsError::NTStatus::STATUS_OBJECT_NAME_NOT_FOUND)
      expect { pipe.peek }.to raise_error(RubySMB::Error::UnexpectedStatusCode)
    end

    it 'returns the expected response' do
      expect(pipe.peek).to eq(response)
    end
  end

  describe '#peek_available' do
    it 'reads the correct number of bytes available' do
      allow(pipe).to receive(:peek) { ioctl_response }
      allow(pipe).to receive(:peek_available) { pipe.peek.buffer.unpack('VV')[1] }
      expect(pipe.peek_available).to eq(0x40302010)
    end
  end

  describe '#peek_state' do
    it 'reads the correct state of the pipe' do
      allow(pipe).to receive(:peek) { ioctl_response }
      allow(pipe).to receive(:peek_state)  { pipe.peek.buffer.unpack('V')[0] }
      expect(pipe.peek_state).to eq(RubySMB::SMB2::Pipe::STATUS_CONNECTED)
    end
  end

  describe '#is_connected?' do
    it 'identifies that the pipe is connected from the status' do
      allow(pipe).to receive(:peek) { ioctl_response }
      allow(pipe).to receive(:peek_state)  { pipe.peek.buffer.unpack('V')[0] }
      allow(pipe).to receive(:is_connected?) { pipe.peek_state == RubySMB::SMB2::Pipe::STATUS_CONNECTED }
      expect(pipe.is_connected?).to eq(true)
    end
  end

  context 'with DCERPC' do
    describe '#net_share_enum_all' do
      let(:host) { '1.2.3.4' }
      let(:dcerpc_response) { RubySMB::Dcerpc::Response.new }

      before :example do
        allow(pipe).to receive(:bind)
        allow(pipe).to receive(:request).and_return(dcerpc_response)
        allow(RubySMB::Dcerpc::Srvsvc::NetShareEnumAll).to receive(:parse_response).and_return([])
      end

      it 'calls #bind with the expected arguments' do
        expect(pipe).to receive(:bind).with(endpoint: RubySMB::Dcerpc::Srvsvc)
        pipe.net_share_enum_all(host)
      end

      it 'calls #request with the expected arguments' do
        expect(pipe).to receive(:request).with(RubySMB::Dcerpc::Srvsvc::NET_SHARE_ENUM_ALL, host: host)
        pipe.net_share_enum_all(host)
      end

      it 'parse the response with NetShareEnumAll #parse_response method' do
        stub = 'ABCD'
        dcerpc_response.alloc_hint = stub.size
        dcerpc_response.stub = stub
        expect(RubySMB::Dcerpc::Srvsvc::NetShareEnumAll).to receive(:parse_response).with(stub)
        pipe.net_share_enum_all(host)
      end

      it 'returns the remote shares' do
        shares = [
          ["C$", "DISK", "Default share"],
          ["Shared", "DISK", ""],
          ["IPC$", "IPC", "Remote IPC"],
          ["ADMIN$", "DISK", "Remote Admin"]
        ]
        output = [
          {:name=>"C$", :type=>"DISK", :comment=>"Default share"},
          {:name=>"Shared", :type=>"DISK", :comment=>""},
          {:name=>"IPC$", :type=>"IPC", :comment=>"Remote IPC"},
          {:name=>"ADMIN$", :type=>"DISK", :comment=>"Remote Admin"},
        ]
        allow(RubySMB::Dcerpc::Srvsvc::NetShareEnumAll).to receive(:parse_response).and_return(shares)
        expect(pipe.net_share_enum_all(host)).to eq(output)
      end
    end

    describe '#bind' do
      let(:options) { { endpoint: RubySMB::Dcerpc::Srvsvc } }
      let(:bind_packet) { RubySMB::Dcerpc::Bind.new(options) }
      let(:bind_ack_packet) { RubySMB::Dcerpc::BindAck.new }

      before :example do
        allow(RubySMB::Dcerpc::Bind).to receive(:new).and_return(bind_packet)
        allow(pipe).to receive(:write)
        allow(pipe).to receive(:read)
        bind_ack_packet.p_result_list.n_results = 1
        bind_ack_packet.p_result_list.p_results[0].result = RubySMB::Dcerpc::BindAck::ACCEPTANCE
        allow(RubySMB::Dcerpc::BindAck).to receive(:read).and_return(bind_ack_packet)
      end

      it 'creates a Bind packet' do
        expect(RubySMB::Dcerpc::Bind).to receive(:new).with(options).and_return(bind_packet)
        pipe.bind(options)
      end

      it 'writes to the named pipe' do
        expect(pipe).to receive(:write).with(data: bind_packet.to_binary_s)
        pipe.bind(options)
      end

      it 'reads the socket' do
        expect(pipe).to receive(:read)
        pipe.bind(options)
      end

      it 'creates a BindAck packet from the response' do
        raw_response = RubySMB::Dcerpc::BindAck.new.to_binary_s
        allow(pipe).to receive(:read).and_return(raw_response)
        expect(RubySMB::Dcerpc::BindAck).to receive(:read).with(raw_response).and_return(bind_ack_packet)
        pipe.bind(options)
      end

      it 'raises the expected exception when an invalid packet is received' do
        allow(RubySMB::Dcerpc::BindAck).to receive(:read).and_raise(IOError)
        expect { pipe.bind(options) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
      end

      it 'raises the expected exception when it is not a BindAck packet' do
        response = RubySMB::Dcerpc::Bind.new
        allow(RubySMB::Dcerpc::BindAck).to receive(:read).and_return(response)
        expect { pipe.bind(options) }.to raise_error(RubySMB::Dcerpc::Error::BindError)
      end

      it 'raises an exception when no result is returned' do
        bind_ack_packet.p_result_list.n_results = 0
        expect { pipe.bind(options) }.to raise_error(RubySMB::Dcerpc::Error::BindError)
      end

      it 'raises an exception when result is not ACCEPTANCE' do
        bind_ack_packet.p_result_list.p_results[0].result = RubySMB::Dcerpc::BindAck::USER_REJECTION
        expect { pipe.bind(options) }.to raise_error(RubySMB::Dcerpc::Error::BindError)
      end

      it 'returns the expected BindAck packet' do
        expect(pipe.bind(options)).to eq(bind_ack_packet)
      end
    end

    describe '#request' do
      let(:options) { { host: '1.2.3.4' } }
      let(:opnum) { RubySMB::Dcerpc::Srvsvc::NET_SHARE_ENUM_ALL }
      let(:req_packet) { RubySMB::Dcerpc::Request.new({ :opnum => opnum }, options) }
      let(:ioctl_response) { RubySMB::SMB2::Packet::IoctlResponse.new }
      let(:res_packet) { RubySMB::Dcerpc::Response.new }

      before :example do
        allow(RubySMB::Dcerpc::Request).to receive(:new).and_return(req_packet)
        allow(pipe).to receive(:ioctl_send_recv).and_return(ioctl_response)
        allow(RubySMB::Dcerpc::Response).to receive(:read).and_return(res_packet)
      end

      it 'creates a Request packet' do
        expect(RubySMB::Dcerpc::Request).to receive(:new).and_return(req_packet)
        pipe.request(opnum, options)
      end

      it 'calls #ioctl_send_recv' do
        expect(pipe).to receive(:ioctl_send_recv).with(req_packet, options)
        pipe.request(opnum, options)
      end

      it 'creates a DCERPC Response packet from the response' do
        expect(RubySMB::Dcerpc::Response).to receive(:read).with(ioctl_response.output_data)
        pipe.request(opnum, options)
      end

      it 'raises the expected exception when an invalid packet is received' do
        allow(RubySMB::Dcerpc::Response).to receive(:read).and_raise(IOError)
        expect { pipe.request(opnum, options) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
      end

      it 'raises the expected exception when it is not a BindAck packet' do
        response = RubySMB::Dcerpc::Request.new
        allow(RubySMB::Dcerpc::Response).to receive(:read).and_return(response)
        expect { pipe.request(opnum, options) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
      end

      it 'returns the expected DCERPC Response' do
        expect(pipe.request(opnum, options)).to eq(res_packet)
      end
    end

    describe '#ioctl_send_recv' do
      let(:action) { RubySMB::Dcerpc::Request.new({ :opnum => RubySMB::Dcerpc::Srvsvc::NET_SHARE_ENUM_ALL }, host: '1.2.3.4') }
      let(:options) { {} }
      let(:ioctl_request) { RubySMB::SMB2::Packet::IoctlRequest.new(options) }
      let(:ioctl_response) { RubySMB::SMB2::Packet::IoctlResponse.new }

      before :example do
        allow(client).to receive(:send_recv).and_return(ioctl_response.to_binary_s)
      end

      it 'calls #set_header_fields' do
        expect(pipe).to receive(:set_header_fields).with(ioctl_request).and_call_original
        pipe.ioctl_send_recv(action, options)
      end

      it 'calls Client #send_recv with the expected request' do
        expect(client).to receive(:send_recv) do |req|
          expect(req.ctl_code).to eq(0x0011C017)
          expect(req.flags.is_fsctl).to eq(0x00000001)
          expect(req.buffer).to eq(action.to_binary_s)
          ioctl_response.to_binary_s
        end
        pipe.ioctl_send_recv(action, options)
      end

      it 'creates a IoctlResponse packet from the response' do
        expect(RubySMB::SMB2::Packet::IoctlResponse).to receive(:read).with(ioctl_response.to_binary_s).and_call_original
        pipe.ioctl_send_recv(action, options)
      end

      it 'raises the expected exception when it is not a valid packet' do
        ioctl_response.smb2_header.command = RubySMB::SMB2::Commands::LOGOFF
        allow(RubySMB::SMB2::Packet::IoctlResponse).to receive(:read).and_return(ioctl_response)
        expect { pipe.ioctl_send_recv(action, options) }.to raise_error(RubySMB::Error::InvalidPacket)
      end

      it 'raises the expected exception when the status code is not STATUS_SUCCESS' do
        ioctl_response_packet = RubySMB::SMB2::Packet::IoctlResponse.new
        ioctl_response_packet.smb2_header.nt_status = WindowsError::NTStatus::STATUS_INVALID_HANDLE.value
        allow(RubySMB::SMB2::Packet::IoctlResponse).to receive(:read).with(ioctl_response.to_binary_s).and_return(ioctl_response_packet)
        expect { pipe.ioctl_send_recv(action, options) }.to raise_error(RubySMB::Error::UnexpectedStatusCode)
      end

      it 'returns the expected DCERPC Response' do
        expect(pipe.ioctl_send_recv(action, options)).to eq(ioctl_response)
      end
    end
  end
end

