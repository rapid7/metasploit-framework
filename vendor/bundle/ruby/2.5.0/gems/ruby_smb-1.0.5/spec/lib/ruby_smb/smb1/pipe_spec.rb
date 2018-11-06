RSpec.describe RubySMB::SMB1::Pipe do

  let(:peek_nmpipe_response) {
    packet = RubySMB::SMB1::Packet::Trans::PeekNmpipeResponse.new
    packet.data_block.trans_parameters.read("\x10\x20\x00\x00\x03\x00")
    packet
  }

  describe RubySMB::SMB1::Pipe do
    it { expect(described_class).to be < RubySMB::SMB1::File }
  end

  let(:dispatcher) { RubySMB::Dispatcher::Socket.new(double('socket')) }
  let(:client) { RubySMB::Client.new(dispatcher, username: 'msfadmin', password: 'msfadmin') }
  let(:connect_response) {
    packet = RubySMB::SMB1::Packet::TreeConnectResponse.new
    packet.smb_header.tid = 2051
    packet.parameter_block.guest_access_rights.read("\xff\x01\x1f\x00")
    packet.parameter_block.access_rights.read("\xff\x01\x1f\x01")
    packet
  }
  let(:tree) { RubySMB::SMB1::Tree.new(client: client, share: '\\1.2.3.4\IPC$', response: connect_response) }
  let(:nt_create_andx_response) {
    response = RubySMB::SMB1::Packet::NtCreateAndxResponse.new
    response.parameter_block.ext_file_attributes = { normal: 1 }
    response.parameter_block.fid = 0x4000
    response.parameter_block.last_access_time = DateTime.parse("2017-09-20T1:1:1")
    response.parameter_block.last_change_time = DateTime.parse("2017-09-22T2:2:2")
    response.parameter_block.last_write_time  = DateTime.parse("2017-09-25T3:3:3")
    response.parameter_block.end_of_file = 53
    response.parameter_block.allocation_size = 4096
    response
  }
  let(:filename) { 'msf-pipe' }

  subject(:pipe) {
    described_class.new(tree: tree, response: nt_create_andx_response, name: filename)
  }

  describe '#peek' do
    let(:request) { RubySMB::SMB1::Packet::Trans::PeekNmpipeRequest.new }
    let(:raw_response) { double('Raw response') }
    let(:response) { double('Response') }

    before :example do
      allow(RubySMB::SMB1::Packet::Trans::PeekNmpipeRequest).to receive(:new).and_return(request)
      allow(client).to receive(:send_recv).and_return(raw_response)
      allow(RubySMB::SMB1::Packet::Trans::PeekNmpipeResponse).to receive(:read).and_return(response)
      allow(response).to receive(:valid?).and_return(true)
      allow(response).to receive(:status_code).and_return(WindowsError::NTStatus::STATUS_SUCCESS)
    end

    it 'creates a PeekNmpipeRequest'do
      expect(RubySMB::SMB1::Packet::Trans::PeekNmpipeRequest).to receive(:new)
      pipe.peek
    end

    it 'sets the request #fid field' do
      expect(request).to receive(:fid=).with(pipe.fid)
      pipe.peek
    end

    it 'sets the request #max_data_count fieldto the peek_size argument' do
      peek_size = 5
      pipe.peek(peek_size: peek_size)
      expect(request.parameter_block.max_data_count).to eq(peek_size)
    end

    it 'calls Tree #set_header_fields' do
      expect(tree).to receive(:set_header_fields).with(request)
      pipe.peek
    end

    it 'calls Client #send_recv' do
      expect(client).to receive(:send_recv).with(request)
      pipe.peek
    end

    it 'parses the response as a SMB1 PeekNmpipeResponse packet' do
      expect(RubySMB::SMB1::Packet::Trans::PeekNmpipeResponse).to receive(:read).with(raw_response)
      pipe.peek
    end

    it 'raises an InvalidPacket exception if the response is not valid' do
      allow(response).to receive(:valid?).and_return(false)
      smb_header = double('SMB Header')
      allow(response).to receive(:smb_header).and_return(smb_header)
      allow(smb_header).to receive_messages(:protocol => nil, :command => nil)
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
      allow(pipe).to receive(:peek) { peek_nmpipe_response }
      allow(pipe).to receive(:peek_available) { pipe.peek.data_block.trans_parameters.read_data_available }
      expect(pipe.peek_available).to eq(0x2010)
    end
  end

  describe '#peek_state' do
    it 'reads the correct state of the pipe' do
      allow(pipe).to receive(:peek) { peek_nmpipe_response }
      allow(pipe).to receive(:peek_state) { pipe.peek.data_block.trans_parameters.pipe_state }
      expect(pipe.peek_state).to eq(RubySMB::SMB1::Pipe::STATUS_OK)
    end
  end

  describe '#is_connected?' do
    it 'identifies that the pipe is connected from the status' do
      allow(pipe).to receive(:peek) { peek_nmpipe_response }
      allow(pipe).to receive(:peek_state) { pipe.peek.data_block.trans_parameters.pipe_state }
      allow(pipe).to receive(:is_connected?) { pipe.peek_state == RubySMB::SMB1::Pipe::STATUS_OK }
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
      let(:nmpipe_packet) { RubySMB::SMB1::Packet::Trans::TransactNmpipeRequest.new(options) }
      let(:nmpipe_response) { RubySMB::SMB1::Packet::Trans::TransactNmpipeResponse.new }
      let(:res_packet) { RubySMB::Dcerpc::Response.new }

      before :example do
        allow(RubySMB::Dcerpc::Request).to receive(:new).and_return(req_packet)
        allow(RubySMB::SMB1::Packet::Trans::TransactNmpipeRequest).to receive(:new).and_return(nmpipe_packet)
        allow(client).to receive(:send_recv)
        allow(RubySMB::SMB1::Packet::Trans::TransactNmpipeResponse).to receive(:read).and_return(nmpipe_response)
        allow(RubySMB::Dcerpc::Response).to receive(:read).and_return(res_packet)
      end

      it 'creates a Request packet' do
        expect(RubySMB::Dcerpc::Request).to receive(:new).and_return(req_packet)
        pipe.request(opnum, options)
      end

      it 'creates a Trans TransactNmpipeRequest packet' do
        expect(RubySMB::SMB1::Packet::Trans::TransactNmpipeRequest).to receive(:new).and_return(nmpipe_packet)
        pipe.request(opnum, options)
      end

      it 'calls Tree #set_header_fields' do
        expect(tree).to receive(:set_header_fields).with(nmpipe_packet)
        pipe.request(opnum, options)
      end

      it 'calls TransactNmpipeRequest #set_fid' do
        expect(nmpipe_packet).to receive(:set_fid).with(pipe.fid)
        pipe.request(opnum, options)
      end

      it 'sets the expected data on the request' do
        expect(client).to receive(:send_recv) do
          expect(nmpipe_packet.data_block.trans_data.write_data).to eq(req_packet.to_binary_s)
        end
        pipe.request(opnum, options)
      end

      it 'sends the expected request' do
        expect(client).to receive(:send_recv).with(nmpipe_packet)
        pipe.request(opnum, options)
      end

      it 'creates a Trans TransactNmpipeResponse packet from the response' do
        raw_response = double('Raw response')
        allow(client).to receive(:send_recv).and_return(raw_response)
        expect(RubySMB::SMB1::Packet::Trans::TransactNmpipeResponse).to receive(:read).with(raw_response).and_return(nmpipe_response)
        pipe.request(opnum, options)
      end

      it 'raises the expected exception when it is not a Trans packet' do
        nmpipe_response.smb_header.command = RubySMB::SMB1::Commands::SMB_COM_TRANSACTION2
        expect { pipe.request(opnum, options) }.to raise_error(RubySMB::Error::InvalidPacket)
      end

      it 'raises the expected exception when the status code is not STATUS_SUCCESS' do
        nmpipe_response.smb_header.nt_status = WindowsError::NTStatus::STATUS_INVALID_HANDLE.value
        expect { pipe.request(opnum, options) }.to raise_error(RubySMB::Error::UnexpectedStatusCode)
      end

      it 'creates a DCERPC Response packet from the response' do
        nmpipe_response.data_block.trans_data.read_data = "test"
        expect(RubySMB::Dcerpc::Response).to receive(:read).with(nmpipe_response.data_block.trans_data.read_data)
        pipe.request(opnum, options)
      end

      it 'raises the expected exception when an invalid packet is received' do
        allow(RubySMB::Dcerpc::Response).to receive(:read).and_raise(IOError)
        expect { pipe.request(opnum, options) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
      end

      it 'raises the expected exception when it is not a Response packet' do
        response = RubySMB::Dcerpc::Request.new
        allow(RubySMB::Dcerpc::Response).to receive(:read).and_return(response)
        expect { pipe.request(opnum, options) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
      end

      it 'returns the expected DCERPC Response' do
        expect(pipe.request(opnum, options)).to eq(res_packet)
      end
    end
  end

end
