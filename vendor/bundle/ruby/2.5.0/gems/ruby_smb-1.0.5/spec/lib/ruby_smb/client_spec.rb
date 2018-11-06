require 'spec_helper'

RSpec.describe RubySMB::Client do
  let(:sock) { double('Socket', peeraddr: '192.168.1.5') }
  let(:dispatcher) { RubySMB::Dispatcher::Socket.new(sock) }
  let(:username) { 'msfadmin' }
  let(:password) { 'msfpasswd' }
  subject(:client) { described_class.new(dispatcher, username: username, password: password) }
  let(:smb1_client) { described_class.new(dispatcher, smb2: false, username: username, password: password) }
  let(:smb2_client) { described_class.new(dispatcher, smb1: false, username: username, password: password) }
  let(:empty_packet) { RubySMB::SMB1::Packet::EmptyPacket.new }
  let(:error_packet) { RubySMB::SMB2::Packet::ErrorPacket.new }

  describe '#initialize' do
    it 'should raise an ArgumentError without a valid dispatcher' do
      expect { described_class.new(nil) }.to raise_error(ArgumentError)
    end

    it 'defaults to true for SMB1 support' do
      expect(client.smb1).to be true
    end

    it 'defaults to true for SMB2 support' do
      expect(client.smb1).to be true
    end

    it 'accepts an argument to disable smb1 support' do
      expect(smb2_client.smb1).to be false
    end

    it 'accepts an argument to disable smb2 support' do
      expect(smb1_client.smb2).to be false
    end

    it 'raises an exception if both SMB1 and SMB2 are disabled' do
      expect { described_class.new(dispatcher, smb1: false, smb2: false, username: username, password: password) }.to raise_error(ArgumentError, 'You must enable at least one Protocol')
    end

    it 'sets the username attribute' do
      expect(client.username).to eq username
    end

    it 'sets the password attribute' do
      expect(client.password).to eq password
    end

    it 'creates an NTLM client' do
      expect(client.ntlm_client).to be_a Net::NTLM::Client
    end

    it 'passes the expected arguments when creating the NTLM client' do
      domain = 'SPEC_DOMAIN'
      local_workstation = 'SPEC_WORKSTATION'

      allow(Net::NTLM::Client).to receive(:new) do |username, passwd, opt|
        expect(username).to eq(username)
        expect(password).to eq(password)
        expect(opt[:workstation]).to eq(local_workstation)
        expect(opt[:domain]).to eq(domain)
        flags = Net::NTLM::Client::DEFAULT_FLAGS |
          Net::NTLM::FLAGS[:TARGET_INFO] | 0x02000000
        expect(opt[:flags]).to eq(flags)
      end

      described_class.new(
        dispatcher,
        username: username,
        password: password,
        domain: domain,
        local_workstation: local_workstation
      )
    end

    it 'sets the max_buffer_size to MAX_BUFFER_SIZE' do
      expect(client.max_buffer_size).to eq RubySMB::Client::MAX_BUFFER_SIZE
    end
  end

  describe '#send_recv' do
    let(:smb1_request) { RubySMB::SMB1::Packet::TreeConnectRequest.new }
    let(:smb2_request) { RubySMB::SMB2::Packet::TreeConnectRequest.new }

    before(:each) do
      expect(dispatcher).to receive(:send_packet).and_return(nil)
      expect(dispatcher).to receive(:recv_packet).and_return('A')
    end

    it 'checks the packet version' do
      expect(smb1_request).to receive(:packet_smb_version).and_call_original
      client.send_recv(smb1_request)
    end

    it 'calls #smb1_sign if it is an SMB1 packet' do
      expect(client).to receive(:smb1_sign).with(smb1_request).and_call_original
      client.send_recv(smb1_request)
    end

    it 'calls #smb2_sign if it is an SMB2 packet' do
      expect(client).to receive(:smb2_sign).with(smb2_request).and_call_original
      client.send_recv(smb2_request)
    end
  end

  describe '#login' do
    before(:each) do
      allow(client).to receive(:negotiate)
      allow(client).to receive(:authenticate)
    end

    it 'defaults username to what was in the initializer' do
      expect { client.login }.to_not change(client, :username)
    end

    it 'overrides username if it is passed as a parameter' do
      expect { client.login(username: 'test') }.to change(client, :username).to('test')
    end

    it 'defaults password to what was in the initializer' do
      expect { client.login }.to_not change(client, :password)
    end

    it 'overrides password if it is passed as a parameter' do
      expect { client.login(password: 'test') }.to change(client, :password).to('test')
    end

    it 'defaults domain to what was in the initializer' do
      expect { client.login }.to_not change(client, :domain)
    end

    it 'overrides domain if it is passed as a parameter' do
      expect { client.login(domain: 'test') }.to change(client, :domain).to('test')
    end

    it 'defaults local_workstation to what was in the initializer' do
      expect { client.login }.to_not change(client, :local_workstation)
    end

    it 'overrides local_workstation if it is passed as a parameter' do
      expect { client.login(local_workstation: 'test') }.to change(client, :local_workstation).to('test')
    end

    it 'initialises a new NTLM Client' do
      expect { client.login }.to change(client, :ntlm_client)
    end

    it 'calls negotiate after the setup' do
      expect(client).to receive(:negotiate)
      client.login
    end

    it 'calls authenticate after negotiate' do
      expect(client).to receive(:authenticate)
      client.login
    end
  end

  describe '#logoff!' do
    context 'with SMB1' do
      let(:raw_response) { double('Raw response') }
      let(:logoff_response) {
        RubySMB::SMB1::Packet::LogoffResponse.new(smb_header: {:command => RubySMB::SMB1::Commands::SMB_COM_LOGOFF} )
      }
      before :example do
        allow(smb1_client).to receive(:send_recv).and_return(raw_response)
        allow(RubySMB::SMB1::Packet::LogoffResponse).to receive(:read).and_return(logoff_response)
        allow(smb1_client).to receive(:wipe_state!)
      end

      it 'creates a LogoffRequest packet' do
        expect(RubySMB::SMB1::Packet::LogoffRequest).to receive(:new).and_call_original
        smb1_client.logoff!
      end

      it 'calls #send_recv' do
        expect(smb1_client).to receive(:send_recv)
        smb1_client.logoff!
      end

      it 'reads the raw response as a LogoffResponse packet' do
        expect(RubySMB::SMB1::Packet::LogoffResponse).to receive(:read).with(raw_response)
        smb1_client.logoff!
      end

      it 'raise an InvalidPacket exception when the response is an empty packet' do
        allow(RubySMB::SMB1::Packet::LogoffResponse).to receive(:read).and_return(RubySMB::SMB1::Packet::EmptyPacket.new)
        expect {smb1_client.logoff!}.to raise_error(RubySMB::Error::InvalidPacket)
      end

      it 'raise an InvalidPacket exception when the response is not valid' do
        allow(logoff_response).to receive(:valid?).and_return(false)
        expect {smb1_client.logoff!}.to raise_error(RubySMB::Error::InvalidPacket)
      end

      it 'calls #wipe_state!' do
        expect(smb1_client).to receive(:wipe_state!)
        smb1_client.logoff!
      end

      it 'returns the expected status code' do
        logoff_response.smb_header.nt_status = WindowsError::NTStatus::STATUS_PENDING.value
        allow(RubySMB::SMB1::Packet::LogoffResponse).to receive(:read).and_return(logoff_response)
        expect(smb1_client.logoff!).to eq(WindowsError::NTStatus::STATUS_PENDING)
      end
    end

    context 'with SMB2' do
      let(:raw_response) { double('Raw response') }
      let(:logoff_response) {
        RubySMB::SMB2::Packet::LogoffResponse.new(smb_header: {:command => RubySMB::SMB2::Commands::LOGOFF} )
      }
      before :example do
        allow(smb2_client).to receive(:send_recv).and_return(raw_response)
        allow(RubySMB::SMB2::Packet::LogoffResponse).to receive(:read).and_return(logoff_response)
        allow(smb2_client).to receive(:wipe_state!)
      end

      it 'creates a LogoffRequest packet' do
        expect(RubySMB::SMB2::Packet::LogoffRequest).to receive(:new).and_call_original
        smb2_client.logoff!
      end

      it 'calls #send_recv' do
        expect(smb2_client).to receive(:send_recv)
        smb2_client.logoff!
      end

      it 'reads the raw response as a LogoffResponse packet' do
        expect(RubySMB::SMB2::Packet::LogoffResponse).to receive(:read).with(raw_response)
        smb2_client.logoff!
      end

      it 'raise an InvalidPacket exception when the response is an error packet' do
        allow(RubySMB::SMB2::Packet::LogoffResponse).to receive(:read).and_return(RubySMB::SMB2::Packet::ErrorPacket.new)
        expect {smb2_client.logoff!}.to raise_error(RubySMB::Error::InvalidPacket)
      end

      it 'raise an InvalidPacket exception when the response is not a LOGOFF command' do
        logoff_response.smb2_header.command = RubySMB::SMB2::Commands::ECHO
        allow(RubySMB::SMB2::Packet::LogoffResponse).to receive(:read).and_return(logoff_response)
        expect {smb2_client.logoff!}.to raise_error(RubySMB::Error::InvalidPacket)
      end
    end
  end

  context 'NetBIOS Session Service' do
    describe '#session_request' do
      let(:session_header)  { RubySMB::Nbss::SessionHeader.new }
      let(:session_request) { RubySMB::Nbss::SessionRequest.new }

      before :example do
        allow(RubySMB::Nbss::SessionRequest).to receive(:new).and_return(session_request)
        allow(dispatcher).to receive(:send_packet)
        allow(dispatcher).to receive(:recv_packet).and_return(session_header.to_binary_s)
      end

      it 'calls #session_request_packet' do
        called_name = 'SPECNAME'
        expect(client).to receive(:session_request_packet).with(called_name)
        client.session_request(called_name)
      end

      it 'sends the SessionRequest packet without adding additional NetBIOS Session Header' do
        expect(dispatcher).to receive(:send_packet).with(session_request, nbss_header: false)
        client.session_request
      end

      it 'reads the full response packet, including the NetBIOS Session Header' do
        expect(dispatcher).to receive(:recv_packet).with(full_response: true).and_return(session_header.to_binary_s)
        client.session_request
      end

      it 'parses the response with SessionHeader packet structure' do
        expect(RubySMB::Nbss::SessionHeader).to receive(:read).with(session_header.to_binary_s).and_return(session_header)
        client.session_request
      end

      it 'returns true when it is a POSITIVE_SESSION_RESPONSE' do
        session_header.session_packet_type = RubySMB::Nbss::POSITIVE_SESSION_RESPONSE
        expect(client.session_request).to be true
      end

      it 'raises an exception when it is a NEGATIVE_SESSION_RESPONSE' do
        negative_session_response = RubySMB::Nbss::NegativeSessionResponse.new
        negative_session_response.session_header.session_packet_type = RubySMB::Nbss::NEGATIVE_SESSION_RESPONSE
        negative_session_response.error_code = 0x80
        allow(dispatcher).to receive(:recv_packet).and_return(negative_session_response.to_binary_s)
        expect { client.session_request }.to raise_error(RubySMB::Error::NetBiosSessionService)
      end

      it 'raises an InvalidPacket exception when an error occurs while reading' do
        allow(RubySMB::Nbss::SessionHeader).to receive(:read).and_raise(IOError)
        expect { client.session_request }.to raise_error(RubySMB::Error::InvalidPacket)
      end
    end

    describe '#session_request_packet' do
      it 'creates a SessionRequest packet' do
        session_request = RubySMB::Nbss::SessionRequest.new
        expect(RubySMB::Nbss::SessionRequest).to receive(:new).and_return(session_request)
        client.session_request_packet
      end

      it 'sets the expected fields of the SessionRequest packet' do
        name         = 'NBNAMESPEC'
        called_name  = 'NBNAMESPEC      '
        calling_name = "               \x00"

        session_packet = client.session_request_packet(name)
        expect(session_packet).to be_a(RubySMB::Nbss::SessionRequest)
        expect(session_packet.session_header.session_packet_type).to eq RubySMB::Nbss::SESSION_REQUEST
        expect(session_packet.called_name).to eq called_name
        expect(session_packet.calling_name).to eq calling_name
        expect(session_packet.session_header.packet_length).to eq(
          session_packet.called_name.to_binary_s.size + session_packet.calling_name.to_binary_s.size
        )
      end

      it 'converts the called name to upperase' do
        name = 'myname'
        session_packet = client.session_request_packet(name)
        expect(session_packet.called_name).to eq("#{name.upcase.ljust(15)}\x20")
      end

      it 'returns a session packet with *SMBSERVER by default' do
        expect(client.session_request_packet.called_name).to eq('*SMBSERVER      ')
      end
    end
  end

  context 'Protocol Negotiation' do
    let(:random_junk) { 'fgrgrwgawrtw4t4tg4gahgn' }
    let(:smb1_capabilities) {
      { level_2_oplocks: 1,
        nt_status: 1,
        rpc_remote_apis: 1,
        nt_smbs: 1,
        large_files: 1,
        unicode: 1,
        mpx_mode: 0,
        raw_mode: 0,
        large_writex: 1,
        large_readx: 1,
        info_level_passthru: 1,
        dfs: 0,
        reserved1: 0,
        bulk_transfer: 0,
        nt_find: 1,
        lock_and_read: 1,
        unix: 0,
        reserved2: 0,
        lwio: 1,
        extended_security: 1,
        reserved3: 0,
        dynamic_reauth: 0,
        reserved4: 0,
        compressed_data: 0,
        reserved5: 0 }
    }
    let(:smb1_extended_response) {
      packet = RubySMB::SMB1::Packet::NegotiateResponseExtended.new
      packet.parameter_block.capabilities = smb1_capabilities
      packet
    }
    let(:smb1_extended_response_raw) {
      smb1_extended_response.to_binary_s
    }

    let(:smb2_response) { RubySMB::SMB2::Packet::NegotiateResponse.new }

    describe '#smb1_negotiate_request' do
      it 'returns an SMB1 Negotiate Request packet' do
        expect(client.smb1_negotiate_request).to be_a(RubySMB::SMB1::Packet::NegotiateRequest)
      end

      it 'sets the default SMB1 Dialect' do
        expect(client.smb1_negotiate_request.dialects).to include(buffer_format: 2, dialect_string: RubySMB::Client::SMB1_DIALECT_SMB1_DEFAULT)
      end

      it 'sets the SMB2.02 dialect if SMB2 support is enabled' do
        expect(client.smb1_negotiate_request.dialects).to include(buffer_format: 2, dialect_string: RubySMB::Client::SMB1_DIALECT_SMB2_DEFAULT)
      end

      it 'excludes the SMB2.02 Dialect if SMB2 support is disabled' do
        expect(smb1_client.smb1_negotiate_request.dialects).to_not include(buffer_format: 2, dialect_string: RubySMB::Client::SMB1_DIALECT_SMB2_DEFAULT)
      end

      it 'excludes the default SMB1 Dialect if SMB1 support is disabled' do
        expect(smb2_client.smb1_negotiate_request.dialects).to_not include(buffer_format: 2, dialect_string: RubySMB::Client::SMB1_DIALECT_SMB1_DEFAULT)
      end
    end

    describe '#smb2_negotiate_request' do
      it 'return an SMB2 Negotiate Request packet' do
        expect(client.smb2_negotiate_request).to be_a(RubySMB::SMB2::Packet::NegotiateRequest)
      end

      it 'sets the default SMB2 Dialect' do
        expect(client.smb2_negotiate_request.dialects).to include(RubySMB::Client::SMB2_DIALECT_DEFAULT)
      end

      it 'sets the Message ID to 0' do
        expect(client.smb2_negotiate_request.smb2_header.message_id).to eq 0
      end
    end

    describe '#negotiate_request' do
      it 'calls #smb1_negotiate_request if SMB1 is enabled' do
        expect(smb1_client).to receive(:smb1_negotiate_request)
        smb1_client.negotiate_request
      end

      it 'calls #smb1_negotiate_request if both protocols are enabled' do
        expect(client).to receive(:smb1_negotiate_request)
        client.negotiate_request
      end

      it 'calls #smb2_negotiate_request if SMB2 is enabled' do
        expect(smb2_client).to receive(:smb2_negotiate_request)
        smb2_client.negotiate_request
      end
    end

    describe '#negotiate_response' do
      context 'with only SMB1' do
        it 'returns a properly formed packet' do
          expect(smb1_client.negotiate_response(smb1_extended_response_raw)).to eq smb1_extended_response
        end

        it 'raises an exception if the response is not a SMB packet' do
          expect { smb1_client.negotiate_response(random_junk) }.to raise_error(RubySMB::Error::InvalidPacket)
        end

        it 'raises an InvalidPacket error if the response is not a valid response' do
          empty_packet.smb_header.command = RubySMB::SMB2::Commands::NEGOTIATE
          expect { smb1_client.negotiate_response(empty_packet.to_binary_s) }.to raise_error(RubySMB::Error::InvalidPacket)
        end

        it 'considers the response invalid if it is not an actual Negotiate Response' do
          bogus_response = smb1_extended_response
          bogus_response.smb_header.command = 0xff
          expect { smb1_client.negotiate_response(bogus_response.to_binary_s) }.to raise_error(RubySMB::Error::InvalidPacket)
        end

        it 'considers the response invalid if Extended Security is not enabled' do
          bogus_response = smb1_extended_response
          bogus_response.parameter_block.capabilities.extended_security = 0
          expect { smb1_client.negotiate_response(bogus_response.to_binary_s) }.to raise_error(RubySMB::Error::InvalidPacket)
        end
      end

      context 'with only SMB2' do
        it 'returns a properly formed packet' do
          expect(smb2_client.negotiate_response(smb2_response.to_binary_s)).to eq smb2_response
        end

        it 'raises an exception if the Response is invalid' do
          expect { smb2_client.negotiate_response(random_junk) }.to raise_error(RubySMB::Error::InvalidPacket)
        end

        it 'considers the response invalid if it is not an actual Negotiate Response' do
          bogus_response = smb2_response
          bogus_response.smb2_header.command = RubySMB::SMB2::Commands::ECHO
          expect { smb2_client.negotiate_response(bogus_response.to_binary_s) }.to raise_error(RubySMB::Error::InvalidPacket)
        end
      end

      context 'with SMB1 and SMB2 enabled' do
        it 'returns an SMB1 NegotiateResponse if it looks like SMB1' do
          expect(client.negotiate_response(smb1_extended_response_raw)).to eq smb1_extended_response
        end

        it 'returns an SMB2 NegotiateResponse if it looks like SMB2' do
          expect(client.negotiate_response(smb2_response.to_binary_s)).to eq smb2_response
        end
      end
    end

    describe '#parse_negotiate_response' do
      context 'when SMB1 was Negotiated' do
        it 'turns off SMB2 support' do
          client.parse_negotiate_response(smb1_extended_response)
          expect(client.smb2).to be false
        end

        it 'sets whether or not signing is required' do
          smb1_extended_response.parameter_block.security_mode.security_signatures_required = 1
          client.parse_negotiate_response(smb1_extended_response)
          expect(client.signing_required).to be true
        end

        it 'sets #dialect to the negotiated dialect' do
          smb1_extended_response.dialects = [
            RubySMB::SMB1::Dialect.new(dialect_string: 'A'),
            RubySMB::SMB1::Dialect.new(dialect_string: 'B'),
            RubySMB::SMB1::Dialect.new(dialect_string: 'C'),
          ]
          smb1_extended_response.parameter_block.dialect_index = 1
          client.parse_negotiate_response(smb1_extended_response)
          expect(client.dialect).to eq 'B'
        end

        it 'returns the string \'SMB1\'' do
          expect(client.parse_negotiate_response(smb1_extended_response)).to eq ('SMB1')
        end
      end

      context 'when SMB2 was negotiated' do
        it 'turns off SMB1 support' do
          client.parse_negotiate_response(smb2_response)
          expect(client.smb1).to be false
        end

        it 'sets whether or not signing is required' do
          smb2_response.security_mode.signing_required = 1
          client.parse_negotiate_response(smb2_response)
          expect(client.signing_required).to be true
        end

        it 'sets #dialect to the negotiated dialect' do
          smb2_response.dialect_revision = 2
          client.parse_negotiate_response(smb2_response)
          expect(client.dialect).to eq '0x0002'
        end

        it 'returns the string \'SMB2\'' do
          expect(client.parse_negotiate_response(smb2_response)).to eq ('SMB2')
        end
      end
    end

    describe '#negotiate' do
      it 'calls the backing methods' do
        expect(client).to receive(:negotiate_request)
        expect(client).to receive(:send_recv)
        expect(client).to receive(:negotiate_response)
        expect(client).to receive(:parse_negotiate_response)
        client.negotiate
      end

      it 'sets the response-packet #dialects array with the dialects sent in the request' do
        request_packet = client.smb1_negotiate_request
        allow(client).to receive(:negotiate_request).and_return(request_packet)
        allow(client).to receive(:send_recv)
        allow(client).to receive(:negotiate_response).and_return(smb1_extended_response)
        expect(smb1_extended_response).to receive(:dialects=).with(request_packet.dialects)
        client.negotiate
      end

      it 'raise the expected exception if an error occurs' do
        allow(client).to receive(:send_recv).and_raise(RubySMB::Error::InvalidPacket)
        expect { client.negotiate }.to raise_error(RubySMB::Error::NegotiationFailure)
      end
    end
  end

  context 'Authentication' do
    let(:type2_string) {
      "TlRMTVNTUAACAAAAHgAeADgAAAA1goriwmZ8HEHtFHAAAAAAAAAAAJgAmABW\nAAAABgGxHQAAAA" \
        "9XAEkATgAtAFMATgBKAEQARwAwAFUAQQA5ADAARgACAB4A\nVwBJAE4ALQBTAE4ASgBEAEcAMABV" \
        "AEEAOQAwAEYAAQAeAFcASQBOAC0AUwBO\nAEoARABHADAAVQBBADkAMABGAAQAHgBXAEkATgAtAF" \
        "MATgBKAEQARwAwAFUA\nQQA5ADAARgADAB4AVwBJAE4ALQBTAE4ASgBEAEcAMABVAEEAOQAwAEYABw" \
        "AI\nADxThZ4nnNIBAAAAAA==\n"
    }

    describe '#authenticate' do
      it 'calls #smb2_authenticate if SMB2 was selected/negotiated' do
        expect(smb2_client).to receive(:smb2_authenticate)
        smb2_client.authenticate
      end

      it 'calls #smb1_authenticate if SMB1 was selected and we have credentials' do
        expect(smb1_client).to receive(:smb1_authenticate)
        smb1_client.authenticate
      end

      it 'calls #smb1_anonymous_auth if using SMB1 and no credentials were supplied' do
        smb1_client.username = ''
        smb1_client.password = ''
        expect(smb1_client).to receive(:smb1_anonymous_auth)
        smb1_client.authenticate
      end
    end

    context 'for SMB1' do
      let(:ntlm_client) { smb1_client.ntlm_client }
      let(:type1_message) { ntlm_client.init_context }
      let(:negotiate_packet) { RubySMB::SMB1::Packet::SessionSetupRequest.new }
      let(:response_packet) { RubySMB::SMB1::Packet::SessionSetupResponse.new }
      let(:final_response_packet) { RubySMB::SMB1::Packet::SessionSetupResponse.new }
      let(:type3_message) { ntlm_client.init_context(type2_string) }
      let(:user_id) { 2041 }

      describe '#smb1_authenticate' do
        before :example do
          allow(smb1_client).to receive(:smb1_ntlmssp_negotiate)
          allow(smb1_client).to receive(:smb1_ntlmssp_challenge_packet).and_return(response_packet)
          allow(smb1_client).to receive(:smb1_type2_message).and_return(type2_string)
          allow(smb1_client).to receive(:smb1_ntlmssp_authenticate)
          allow(smb1_client).to receive(:smb1_ntlmssp_final_packet).and_return(final_response_packet)
        end

        it 'calls the backing methods' do
          response_packet.smb_header.uid = user_id
          expect(smb1_client).to receive(:smb1_ntlmssp_negotiate).and_return(negotiate_packet)
          expect(smb1_client).to receive(:smb1_ntlmssp_challenge_packet).with(negotiate_packet).and_return(response_packet)
          expect(smb1_client).to receive(:smb1_type2_message).with(response_packet).and_return(type2_string)
          expect(smb1_client).to receive(:store_target_info).with(String)
          expect(smb1_client).to receive(:extract_os_version).with(String)
          expect(smb1_client).to receive(:smb1_ntlmssp_authenticate).with(Net::NTLM::Message::Type3, user_id)
          expect(smb1_client).to receive(:smb1_ntlmssp_final_packet).and_return(final_response_packet)
          smb1_client.smb1_authenticate
        end

        it 'stores the OS information from the challenge packet' do
          native_os = 'Windows 7 Professional 7601 Service Pack 1'
          native_lm = 'Windows 7 Professional 6.1'
          response_packet.data_block.native_os = native_os
          response_packet.data_block.native_lan_man = native_lm
          smb1_client.smb1_authenticate

          expect(smb1_client.peer_native_os).to eq native_os
          expect(smb1_client.peer_native_lm).to eq native_lm
        end

        it 'stores the session key from the NTLM client' do
          smb1_client.smb1_authenticate
          expect(smb1_client.session_key).to eq ntlm_client.session_key
        end

        it 'stores the OS version number from the challenge message' do
          smb1_client.smb1_authenticate
          expect(smb1_client.os_version).to eq '6.1.7601'
        end

        it 'stores the user ID if the status code is \'STATUS_SUCCESS\'' do
          response_packet.smb_header.uid = user_id
          final_response_packet.smb_header.nt_status = WindowsError::NTStatus::STATUS_SUCCESS.value
          smb1_client.smb1_authenticate
          expect(smb1_client.user_id).to eq user_id
        end

        it 'does not store the user ID if the status code is not \'STATUS_SUCCESS\'' do
          response_packet.smb_header.uid = user_id
          final_response_packet.smb_header.nt_status = WindowsError::NTStatus::STATUS_PENDING.value
          smb1_client.smb1_authenticate
          expect(smb1_client.user_id).to eq nil
        end
      end

      describe '#smb1_ntlmssp_auth_packet' do
        it 'creates a new SessionSetupRequest packet' do
          expect(RubySMB::SMB1::Packet::SessionSetupRequest).to receive(:new).and_return(negotiate_packet)
          smb1_client.smb1_ntlmssp_auth_packet(type3_message, user_id)
        end

        it 'sets the security blob with an NTLM Type 3 Message' do
          expect(RubySMB::SMB1::Packet::SessionSetupRequest).to receive(:new).and_return(negotiate_packet)
          expect(negotiate_packet).to receive(:set_type3_blob).with(type3_message.serialize)
          smb1_client.smb1_ntlmssp_auth_packet(type3_message, user_id)
        end

        it 'enables extended security on the packet' do
          expect(smb1_client.smb1_ntlmssp_auth_packet(type3_message, user_id).smb_header.flags2.extended_security).to eq 1
        end

        it 'sets the max_buffer_size to the client\'s max_buffer_size' do
          expect(smb1_client.smb1_ntlmssp_auth_packet(type3_message, user_id).parameter_block.max_buffer_size).to eq smb1_client.max_buffer_size
        end
      end

      describe '#smb1_ntlmssp_negotiate_packet' do
        it 'creates a new SessionSetupRequest packet' do
          expect(RubySMB::SMB1::Packet::SessionSetupRequest).to receive(:new).and_return(negotiate_packet)
          smb1_client.smb1_ntlmssp_negotiate_packet
        end

        it 'builds the security blob with an NTLM Type 1 Message' do
          expect(RubySMB::SMB1::Packet::SessionSetupRequest).to receive(:new).and_return(negotiate_packet)
          expect(ntlm_client).to receive(:init_context).and_return(type1_message)
          expect(negotiate_packet).to receive(:set_type1_blob).with(type1_message.serialize)
          smb1_client.smb1_ntlmssp_negotiate_packet
        end

        it 'enables extended security on the packet' do
          expect(smb1_client.smb1_ntlmssp_negotiate_packet.smb_header.flags2.extended_security).to eq 1
        end

        it 'sets the max_buffer_size to the client\'s max_buffer_size' do
          expect(smb1_client.smb1_ntlmssp_negotiate_packet.parameter_block.max_buffer_size).to eq smb1_client.max_buffer_size
        end
      end

      describe '#smb1_ntlmssp_authenticate' do
        it 'sends the request packet and receives a response' do
          expect(smb1_client).to receive(:smb1_ntlmssp_auth_packet).and_return(negotiate_packet)
          expect(dispatcher).to receive(:send_packet).with(negotiate_packet)
          expect(dispatcher).to receive(:recv_packet)
          smb1_client.smb1_ntlmssp_authenticate(type3_message, user_id)
        end
      end

      describe '#smb1_ntlmssp_negotiate' do
        it 'sends the request packet and receives a response' do
          expect(smb1_client).to receive(:smb1_ntlmssp_negotiate_packet).and_return(negotiate_packet)
          expect(dispatcher).to receive(:send_packet).with(negotiate_packet)
          expect(dispatcher).to receive(:recv_packet)
          smb1_client.smb1_ntlmssp_negotiate
        end
      end

      describe '#smb1_ntlmssp_challenge_packet' do
        let(:response) {
          packet = RubySMB::SMB1::Packet::SessionSetupResponse.new
          packet.smb_header.nt_status = 0xc0000016
          packet
        }
        let(:wrong_command) {
          packet = RubySMB::SMB1::Packet::SessionSetupResponse.new
          packet.smb_header.nt_status = 0xc0000016
          packet.smb_header.command = RubySMB::SMB1::Commands::SMB_COM_NEGOTIATE
          packet
        }
        it 'returns the packet object' do
          expect(smb1_client.smb1_ntlmssp_challenge_packet(response.to_binary_s)).to eq response
        end

        it 'raises an UnexpectedStatusCode if the status code is not correct' do
          response.smb_header.nt_status = 0xc0000015
          expect { smb1_client.smb1_ntlmssp_challenge_packet(response.to_binary_s) }.to raise_error(RubySMB::Error::UnexpectedStatusCode)
        end

        it 'raise an InvalidPacket exception when the response is not valid' do
          expect { smb1_client.smb1_ntlmssp_challenge_packet(wrong_command.to_binary_s) }.to raise_error(RubySMB::Error::InvalidPacket)
        end
      end

      describe '#smb1_ntlmssp_final_packet' do
        let(:response) {
          packet = RubySMB::SMB1::Packet::SessionSetupResponse.new
          packet.smb_header.nt_status = 0x00000000
          packet
        }
        let(:wrong_command) {
          packet = RubySMB::SMB1::Packet::SessionSetupResponse.new
          packet.smb_header.nt_status = 0x00000000
          packet.smb_header.command = RubySMB::SMB1::Commands::SMB_COM_NEGOTIATE
          packet
        }
        it 'returns the packet object' do
          expect(smb1_client.smb1_ntlmssp_final_packet(response.to_binary_s)).to eq response
        end

        it 'raise an InvalidPacket exception when the response is not valid' do
          expect { smb1_client.smb1_ntlmssp_final_packet(wrong_command.to_binary_s) }.to raise_error(RubySMB::Error::InvalidPacket)
        end
      end

      describe '#smb1_type2_message' do
        let(:fake_type2) { 'NTLMSSP FOO' }
        let(:response_packet) {
          packet = RubySMB::SMB1::Packet::SessionSetupResponse.new
          packet.set_type2_blob(fake_type2)
          packet
        }
        it 'returns a base64 encoded copy of the Type 2 NTLM message' do
          expect(smb1_client.smb1_type2_message(response_packet)).to eq [fake_type2].pack('m')
        end
      end

      describe 'Anonymous Auth' do
        let(:anonymous_request) { RubySMB::SMB1::Packet::SessionSetupLegacyRequest.new }
        let(:anonymous_response) { RubySMB::SMB1::Packet::SessionSetupLegacyResponse.new }

        describe '#smb1_anonymous_auth' do
          it 'calls the backing methods' do
            expect(client).to receive(:smb1_anonymous_auth_request).and_return(anonymous_request)
            expect(client).to receive(:send_recv).with(anonymous_request)
            expect(client).to receive(:smb1_anonymous_auth_response).and_return(anonymous_response)
            client.smb1_anonymous_auth
          end

          it 'returns the status code' do
            allow(client).to receive(:send_recv)
            allow(client).to receive(:smb1_anonymous_auth_response).and_return(anonymous_response)
            anonymous_response.smb_header.nt_status = WindowsError::NTStatus::STATUS_PENDING.value
            expect(client.smb1_anonymous_auth).to eq WindowsError::NTStatus::STATUS_PENDING
          end

          it 'sets the expected Client\'s attribute from the response when the status code is STATUS_SUCCESS' do
            native_os = 'Windows 7 Professional 7601 Service Pack 1'
            native_lm = 'Windows 7 Professional 6.1'
            primary_domain = 'SPEC_DOMAIN'
            anonymous_response.smb_header.uid = user_id
            anonymous_response.data_block.native_os = native_os
            anonymous_response.data_block.native_lan_man = native_lm
            anonymous_response.data_block.primary_domain = primary_domain
            anonymous_response.smb_header.nt_status = WindowsError::NTStatus::STATUS_SUCCESS.value

            allow(client).to receive(:send_recv)
            allow(client).to receive(:smb1_anonymous_auth_response).and_return(anonymous_response)

            client.smb1_anonymous_auth
            expect(client.user_id).to eq user_id
            expect(client.peer_native_os).to eq native_os
            expect(client.peer_native_lm).to eq native_lm
            expect(client.primary_domain).to eq primary_domain
          end
        end

        describe '#smb1_anonymous_auth_request' do
          it 'creates a SessionSetupLegacyRequest packet with a null byte for the oem password' do
            expect(smb1_client.smb1_anonymous_auth_request.data_block.oem_password).to eq "\x00"
          end

          it 'creates a SessionSetupLegacyRequest packet with the max_buffer_size set to the client\'s max_buffer_size' do
            expect(smb1_client.smb1_anonymous_auth_request.parameter_block.max_buffer_size).to eq smb1_client.max_buffer_size
          end
        end

        describe '#smb1_anonymous_auth_response' do
          it 'returns a Legacy Session SetupResponse Packet' do
            expect(smb1_client.smb1_anonymous_auth_response(anonymous_response.to_binary_s)).to eq anonymous_response
          end

          it 'raise an InvalidPacket exception when the response is not valid' do
            anonymous_response.smb_header.command = RubySMB::SMB1::Commands::SMB_COM_NEGOTIATE
            expect { smb1_client.smb1_anonymous_auth_response(anonymous_response.to_binary_s) }.to raise_error(RubySMB::Error::InvalidPacket)
          end
        end
      end
    end

    context 'for SMB2' do
      let(:ntlm_client) { smb2_client.ntlm_client }
      let(:type1_message) { ntlm_client.init_context }
      let(:negotiate_packet) { RubySMB::SMB2::Packet::SessionSetupRequest.new }
      let(:response_packet) { RubySMB::SMB2::Packet::SessionSetupResponse.new }
      let(:final_response_packet) { RubySMB::SMB2::Packet::SessionSetupResponse.new }
      let(:type3_message) { ntlm_client.init_context(type2_string) }
      let(:session_id) { 0x0000040000000005 }

      describe '#smb2_authenticate' do
        before :example do
          allow(smb2_client).to receive(:smb2_ntlmssp_negotiate)
          allow(smb2_client).to receive(:smb2_ntlmssp_challenge_packet).and_return(response_packet)
          allow(smb2_client).to receive(:smb2_type2_message).and_return(type2_string)
          allow(smb2_client).to receive(:smb2_ntlmssp_authenticate)
          allow(smb2_client).to receive(:smb2_ntlmssp_final_packet).and_return(final_response_packet)
        end

        it 'calls the backing methods' do
          response_packet.smb2_header.session_id = session_id
          expect(smb2_client).to receive(:smb2_ntlmssp_negotiate).and_return(negotiate_packet)
          expect(smb2_client).to receive(:smb2_ntlmssp_challenge_packet).with(negotiate_packet).and_return(response_packet)
          expect(smb2_client).to receive(:smb2_type2_message).with(response_packet).and_return(type2_string)
          expect(smb2_client).to receive(:store_target_info).with(String)
          expect(smb2_client).to receive(:extract_os_version).with(String)
          expect(smb2_client).to receive(:smb2_ntlmssp_authenticate).with(Net::NTLM::Message::Type3, session_id)
          expect(smb2_client).to receive(:smb2_ntlmssp_final_packet).and_return(final_response_packet)
          smb2_client.smb2_authenticate
        end

        it 'stores the session ID from the challenge message' do
          response_packet.smb2_header.session_id = session_id
          smb2_client.smb2_authenticate
          expect(smb2_client.session_id).to eq session_id
        end

        it 'stores the session key from the NTLM client' do
          smb2_client.smb2_authenticate
          expect(smb2_client.session_key).to eq ntlm_client.session_key
        end

        it 'stores the OS version number from the challenge message' do
          smb2_client.smb2_authenticate
          expect(smb2_client.os_version).to eq '6.1.7601'
        end
      end

      describe '#smb2_ntlmssp_negotiate_packet' do
        it 'creates a new SessionSetupRequest packet' do
          expect(RubySMB::SMB2::Packet::SessionSetupRequest).to receive(:new).and_return(negotiate_packet)
          smb2_client.smb2_ntlmssp_negotiate_packet
        end

        it 'builds the security blob with an NTLM Type 1 Message' do
          expect(RubySMB::SMB2::Packet::SessionSetupRequest).to receive(:new).and_return(negotiate_packet)
          expect(ntlm_client).to receive(:init_context).and_return(type1_message)
          expect(negotiate_packet).to receive(:set_type1_blob).with(type1_message.serialize)
          smb2_client.smb2_ntlmssp_negotiate_packet
        end

        it 'sets the message ID in the packet header to 1' do
          expect(smb2_client.smb2_ntlmssp_negotiate_packet.smb2_header.message_id).to eq 1
        end

        it 'increments client#smb2_message_id' do
          expect { smb2_client.smb2_ntlmssp_negotiate_packet }.to change(smb2_client, :smb2_message_id).to(2)
        end
      end

      describe '#smb2_ntlmssp_negotiate' do
        it 'sends the request packet and receives a response' do
          expect(smb2_client).to receive(:smb2_ntlmssp_negotiate_packet).and_return(negotiate_packet)
          expect(dispatcher).to receive(:send_packet).with(negotiate_packet)
          expect(dispatcher).to receive(:recv_packet)
          smb2_client.smb2_ntlmssp_negotiate
        end
      end

      describe '#smb2_ntlmssp_challenge_packet' do
        let(:response) {
          packet = RubySMB::SMB2::Packet::SessionSetupResponse.new
          packet.smb2_header.nt_status = 0xc0000016
          packet
        }
        let(:wrong_command) {
          packet = RubySMB::SMB2::Packet::SessionSetupResponse.new
          packet.smb2_header.nt_status = 0xc0000016
          packet.smb2_header.command = RubySMB::SMB2::Commands::NEGOTIATE
          packet
        }
        it 'returns the packet object' do
          expect(smb2_client.smb2_ntlmssp_challenge_packet(response.to_binary_s)).to eq response
        end

        it 'raises an UnexpectedStatusCode if the status code is not correct' do
          response.smb2_header.nt_status = 0xc0000015
          expect { smb2_client.smb2_ntlmssp_challenge_packet(response.to_binary_s) }.to raise_error(RubySMB::Error::UnexpectedStatusCode)
        end

        it 'raise an InvalidPacket exception when the response is not valid' do
          expect { smb2_client.smb2_ntlmssp_challenge_packet(wrong_command.to_binary_s) }.to raise_error(RubySMB::Error::InvalidPacket)
        end
      end

      describe '#smb2_type2_message' do
        let(:fake_type2) { 'NTLMSSP FOO' }
        let(:response_packet) {
          packet = RubySMB::SMB2::Packet::SessionSetupResponse.new
          packet.set_type2_blob(fake_type2)
          packet
        }
        it 'returns a base64 encoded copy of the Type 2 NTLM message' do
          expect(smb2_client.smb2_type2_message(response_packet)).to eq [fake_type2].pack('m')
        end
      end

      describe '#smb2_ntlmssp_auth_packet' do
        it 'creates a new SessionSetupRequest packet' do
          expect(RubySMB::SMB2::Packet::SessionSetupRequest).to receive(:new).and_return(negotiate_packet)
          smb2_client.smb2_ntlmssp_auth_packet(type3_message, session_id)
        end

        it 'sets the security blob with an NTLM Type 3 Message' do
          expect(RubySMB::SMB2::Packet::SessionSetupRequest).to receive(:new).and_return(negotiate_packet)
          expect(negotiate_packet).to receive(:set_type3_blob).with(type3_message.serialize)
          smb2_client.smb2_ntlmssp_auth_packet(type3_message, session_id)
        end

        it 'sets the session ID on the request packet' do
          expect(smb2_client.smb2_ntlmssp_auth_packet(type3_message, session_id).smb2_header.session_id).to eq session_id
        end
      end

      describe '#smb2_ntlmssp_authenticate' do
        it 'sends the request packet and receives a response' do
          expect(smb2_client).to receive(:smb2_ntlmssp_auth_packet).and_return(negotiate_packet)
          expect(dispatcher).to receive(:send_packet).with(negotiate_packet)
          expect(dispatcher).to receive(:recv_packet)
          smb2_client.smb2_ntlmssp_authenticate(type3_message, session_id)
        end
      end

      describe '#smb2_ntlmssp_final_packet' do
        let(:response) {
          packet = RubySMB::SMB2::Packet::SessionSetupResponse.new
          packet.smb2_header.nt_status = 0x00000000
          packet
        }
        let(:wrong_command) {
          packet = RubySMB::SMB2::Packet::SessionSetupResponse.new
          packet.smb2_header.nt_status = 0x00000000
          packet.smb2_header.command = RubySMB::SMB2::Commands::NEGOTIATE
          packet
        }
        it 'returns the packet object' do
          expect(smb2_client.smb2_ntlmssp_final_packet(response.to_binary_s)).to eq response
        end

        it 'raise an InvalidPacket exception when the response is not valid' do
          expect { smb2_client.smb2_ntlmssp_final_packet(wrong_command.to_binary_s) }.to raise_error(RubySMB::Error::InvalidPacket)
        end
      end
    end

    describe '#store_target_info' do
      let(:target_info_str) { "\x02\x00\x14\x00T\x00E\x00S\x00T\x00D\x00O\x00M"\
        "\x00A\x00I\x00N\x00\x01\x00\x10\x00T\x00E\x00S\x00T\x00N\x00A\x00M"\
        "\x00E\x00\x04\x00 \x00t\x00e\x00s\x00t\x00d\x00o\x00m\x00a\x00i\x00"\
        "n\x00.\x00l\x00o\x00c\x00a\x00l\x00\x03\x002\x00t\x00e\x00s\x00t\x00"\
        "n\x00a\x00m\x00e\x00.\x00t\x00e\x00s\x00t\x00d\x00o\x00m\x00a\x00i"\
        "\x00n\x00.\x00l\x00o\x00c\x00a\x00l\x00\x05\x00 \x00t\x00e\x00s\x00t"\
        "\x00f\x00o\x00r\x00e\x00s\x00t\x00.\x00l\x00o\x00c\x00a\x00l\x00\a"\
        "\x00\b\x00Q7w\x01Fh\xD3\x01\x00\x00\x00\x00" }

      it 'creates a Net::NTLM::TargetInfo object from the target_info string' do
        expect(Net::NTLM::TargetInfo).to receive(:new).with(target_info_str).and_call_original
        client.store_target_info(target_info_str)
      end

      it 'sets the expected Client\'s attribute' do
        client.store_target_info(target_info_str)
        expect(client.default_name).to eq 'TESTNAME'
        expect(client.default_domain).to eq 'TESTDOMAIN'
        expect(client.dns_host_name).to eq 'testname.testdomain.local'
        expect(client.dns_domain_name).to eq 'testdomain.local'
        expect(client.dns_tree_name).to eq 'testforest.local'
      end

      it 'stores the strings with UTF-8 encoding' do
        client.store_target_info(target_info_str)
        expect(client.default_name.encoding.name).to eq 'UTF-8'
        expect(client.default_domain.encoding.name).to eq 'UTF-8'
        expect(client.dns_host_name.encoding.name).to eq 'UTF-8'
        expect(client.dns_domain_name.encoding.name).to eq 'UTF-8'
        expect(client.dns_tree_name.encoding.name).to eq 'UTF-8'
      end
    end

    describe '#extract_os_version' do
      it 'returns the expected version number' do
        expect(client.extract_os_version("\x06\x00q\x17\x00\x00\x00\x0F")).to eq '6.0.6001'
      end
    end
  end

  context 'Signing' do
    describe '#smb2_sign' do
      let(:request1) {
        packet = RubySMB::SMB2::Packet::SessionSetupRequest.new
        packet.smb2_header.flags.signed = 1
        packet.smb2_header.signature = "\x00" * 16
        packet
      }
      let(:fake_hmac) { "\x31\x07\x78\x3e\x35\xd7\x0e\x89\x08\x43\x8a\x18\xcd\x78\x52\x39".force_encoding('ASCII-8BIT') }

      context 'if signing is required and we have a session key' do
        it 'generates the HMAC based on the packet and the NTLM session key and signs the packet with it' do
          smb2_client.session_key = 'foo'
          smb2_client.signing_required = true
          expect(OpenSSL::HMAC).to receive(:digest).with(instance_of(OpenSSL::Digest::SHA256), smb2_client.session_key, request1.to_binary_s).and_return(fake_hmac)
          expect(smb2_client.smb2_sign(request1).smb2_header.signature).to eq fake_hmac
        end
      end

      context 'when signing is not required' do
        it 'returns the packet exactly as it was given' do
          smb2_client.session_key = 'foo'
          smb2_client.signing_required = false
          expect(smb2_client.smb2_sign(request1)).to eq request1
        end
      end

      context 'when there is no session_key' do
        it 'returns the packet exactly as it was given' do
          smb2_client.session_key = ''
          smb2_client.signing_required = true
          expect(smb2_client.smb2_sign(request1)).to eq request1
        end
      end
    end

    describe '#smb1_sign' do
      let(:request1) { RubySMB::SMB1::Packet::SessionSetupRequest.new }
      let(:fake_sig) { "\x9f\x62\xcf\x08\xd9\xc2\x83\x21".force_encoding('ASCII-8BIT') }

      context 'if signing is required and we have a session key' do
        it 'generates the signature based on the packet, the sequence counter and the NTLM session key and signs the packet with it' do
          smb1_client.session_key = 'foo'
          smb1_client.signing_required = true
          raw = request1.to_binary_s
          adjusted_request = RubySMB::SMB1::Packet::SessionSetupRequest.read(raw)
          adjusted_request.smb_header.security_features = [smb1_client.sequence_counter].pack('Q<')
          expect(OpenSSL::Digest::MD5).to receive(:digest).and_return(fake_sig)
          expect(smb1_client.smb1_sign(request1).smb_header.security_features).to eq fake_sig
        end
      end

      context 'when signing is not required' do
        it 'returns the packet exactly as it was given' do
          smb1_client.session_key = 'foo'
          smb1_client.signing_required = false
          expect(smb1_client.smb1_sign(request1)).to eq request1
        end
      end

      context 'when there is no session_key' do
        it 'returns the packet exactly as it was given' do
          smb1_client.session_key = ''
          smb1_client.signing_required = true
          expect(smb1_client.smb1_sign(request1)).to eq request1
        end
      end
    end
  end

  context '#increment_smb_message_id' do
    let(:request_packet) { RubySMB::SMB2::Packet::NegotiateRequest.new }

    it 'sets the message_id on the packet header to the client message_id' do
      id = client.smb2_message_id
      expect(client.increment_smb_message_id(request_packet).smb2_header.message_id).to eq id
    end

    it 'increments the client message id' do
      client.smb2_message_id = 1
      expect { client.increment_smb_message_id(request_packet) }.to change { client.smb2_message_id }.by(1)
    end
  end

  context 'connecting to a share' do
    let(:path) { '\\192.168.1.1\example' }
    let(:tree_id) { 2049 }
    context 'with SMB1' do
      let(:request) { RubySMB::SMB1::Packet::TreeConnectRequest.new }
      let(:response) {
        packet = RubySMB::SMB1::Packet::TreeConnectResponse.new
        packet.smb_header.tid = tree_id
        packet.parameter_block.access_rights.read("\xff\x01\x1f\x00")
        packet.data_block.service = 'A:'
        packet
      }

      describe '#smb1_tree_connect' do
        it 'builds and sends a TreeconnectRequest for the supplied share' do
          allow(RubySMB::SMB1::Packet::TreeConnectRequest).to receive(:new).and_return(request)
          modified_request = request
          modified_request.data_block.path = path
          expect(smb1_client).to receive(:send_recv).with(modified_request).and_return(response.to_binary_s)
          smb1_client.smb1_tree_connect(path)
        end

        it 'sends the response to #smb1_tree_from_response' do
          expect(smb1_client).to receive(:send_recv).and_return(response.to_binary_s)
          expect(smb1_client).to receive(:smb1_tree_from_response).with(path, response)
          smb1_client.smb1_tree_connect(path)
        end
      end

      describe '#smb1_tree_from_response' do
        it 'raises an InvalidPacket exception if the command is not TREE_CONNECT' do
          response.smb_header.command = RubySMB::SMB1::Commands::SMB_COM_NEGOTIATE
          expect { smb1_client.smb1_tree_from_response(path, response) }.to raise_error(RubySMB::Error::InvalidPacket)
        end

        it 'raises an UnexpectedStatusCode exception if we do not get STATUS_SUCCESS' do
          response.smb_header.nt_status = 0xc0000015
          expect { smb1_client.smb1_tree_from_response(path, response) }.to raise_error(RubySMB::Error::UnexpectedStatusCode, 'STATUS_NONEXISTENT_SECTOR')
        end

        it 'creates a new Tree from itself, the share path, and the response packet' do
          expect(RubySMB::SMB1::Tree).to receive(:new).with(client: smb1_client, share: path, response: response)
          smb1_client.smb1_tree_from_response(path, response)
        end
      end
    end

    context 'with SMB2' do
      let(:request) { RubySMB::SMB2::Packet::TreeConnectRequest.new }
      let(:response) {
        packet = RubySMB::SMB2::Packet::TreeConnectResponse.new
        packet.smb2_header.tree_id = tree_id
        packet.maximal_access.read("\xff\x01\x1f\x00")
        packet.share_type = 0x01
        packet
      }

      describe '#smb2_tree_connect' do
        it 'builds and sends a TreeconnectRequest for the supplied share' do
          allow(RubySMB::SMB2::Packet::TreeConnectRequest).to receive(:new).and_return(request)
          modified_request = request
          modified_request.encode_path(path)
          expect(smb2_client).to receive(:send_recv).with(modified_request).and_return(response.to_binary_s)
          smb2_client.smb2_tree_connect(path)
        end

        it 'sends the response to #smb2_tree_from_response' do
          expect(smb2_client).to receive(:send_recv).and_return(response.to_binary_s)
          expect(smb2_client).to receive(:smb2_tree_from_response).with(path, response)
          smb2_client.smb2_tree_connect(path)
        end
      end

      describe '#smb2_tree_from_response' do
        it 'raises an InvalidPacket exception if the command is not TREE_CONNECT' do
          response.smb2_header.command = RubySMB::SMB2::Commands::NEGOTIATE
          expect { smb2_client.smb2_tree_from_response(path, response) }.to raise_error(RubySMB::Error::InvalidPacket)
        end

        it 'raises an UnexpectedStatusCode exception if we do not get STATUS_SUCCESS' do
          response.smb2_header.nt_status = 0xc0000015
          expect { smb2_client.smb2_tree_from_response(path, response) }.to raise_error(RubySMB::Error::UnexpectedStatusCode, 'STATUS_NONEXISTENT_SECTOR')
        end

        it 'creates a new Tree from itself, the share path, and the response packet' do
          expect(RubySMB::SMB2::Tree).to receive(:new).with(client: smb2_client, share: path, response: response)
          smb2_client.smb2_tree_from_response(path, response)
        end
      end

      describe '#net_share_enum_all' do
        let(:tree){ double("Tree") }
        let(:named_pipe){ double("Named Pipe") }

        before :example do
          allow(tree).to receive(:open_file).and_return(named_pipe)
          allow(named_pipe).to receive(:net_share_enum_all)
        end

        context 'with SMB1' do
          before :example do
            allow(smb1_client).to receive(:tree_connect).and_return(tree)
          end

          it 'it calls the #tree_connect method to connect to the "host" IPC$ share' do
            ipc_share = "\\\\#{sock.peeraddr}\\IPC$"
            expect(smb1_client).to receive(:tree_connect).with(ipc_share).and_return(tree)
            smb1_client.net_share_enum_all(sock.peeraddr)
          end

          it 'it calls the Tree #open_file method to open "srvsvc" named pipe' do
            expect(tree).to receive(:open_file).with(filename: "srvsvc", write: true, read: true).and_return(named_pipe)
            smb1_client.net_share_enum_all(sock.peeraddr)
          end

          it 'it calls the File #net_share_enum_all method with the correct host' do
            host = "1.2.3.4"
            expect(named_pipe).to receive(:net_share_enum_all).with(host)
            smb1_client.net_share_enum_all(host)
          end
        end

        context 'with SMB2' do
          before :example do
            allow(smb2_client).to receive(:tree_connect).and_return(tree)
          end

          it 'it calls the #tree_connect method to connect to the "host" IPC$ share' do
            ipc_share = "\\\\#{sock.peeraddr}\\IPC$"
            expect(smb2_client).to receive(:tree_connect).with(ipc_share).and_return(tree)
            smb2_client.net_share_enum_all(sock.peeraddr)
          end

          it 'it calls the Tree #open_file method to open "srvsvc" named pipe' do
            expect(tree).to receive(:open_file).with(filename: "srvsvc", write: true, read: true).and_return(named_pipe)
            smb2_client.net_share_enum_all(sock.peeraddr)
          end

          it 'it calls the File #net_share_enum_all method with the correct host' do
            host = "1.2.3.4"
            expect(named_pipe).to receive(:net_share_enum_all).with(host)
            smb2_client.net_share_enum_all(host)
          end
        end
      end
    end
  end

  context 'Echo command' do
    context 'with SMB1' do
      let(:echo_request) { RubySMB::SMB1::Packet::EchoRequest.new }
      let(:echo_response) {
        packet = RubySMB::SMB1::Packet::EchoResponse.new
        packet.smb_header.nt_status = 0x00000080
        packet
      }

      before(:each) do
        allow(RubySMB::SMB2::Packet::EchoRequest).to receive(:new).and_return(echo_request)
      end

      it 'sets the echo_count on the request packet' do
        modified_request = echo_request
        modified_request.parameter_block.echo_count = 5
        expect(smb1_client).to receive(:send_recv).with(modified_request).and_return(echo_response.to_binary_s)
        expect(dispatcher).to receive(:recv_packet).exactly(4).times.and_return(echo_response.to_binary_s)
        smb1_client.smb1_echo(count: 5)
      end

      it 'sets the data on the request packet' do
        modified_request = echo_request
        modified_request.data_block.data = 'DEADBEEF'
        expect(smb1_client).to receive(:send_recv).with(modified_request).and_return(echo_response.to_binary_s)
        smb1_client.smb1_echo(data: 'DEADBEEF')
      end

      it 'returns the NT status code' do
        expect(smb1_client).to receive(:send_recv).and_return(echo_response.to_binary_s)
        expect(smb1_client.echo).to eq WindowsError::NTStatus::STATUS_ABANDONED
      end

      it 'raise an InvalidPacket exception when the response is not valid' do
        echo_response.smb_header.command = RubySMB::SMB1::Commands::SMB_COM_SESSION_SETUP
        allow(smb1_client).to receive(:send_recv).and_return(echo_response.to_binary_s)
        expect { smb1_client.echo }.to raise_error(RubySMB::Error::InvalidPacket)
      end
    end

    context 'with SMB2' do
      let(:echo_request) { RubySMB::SMB2::Packet::EchoRequest.new }
      let(:echo_response) { RubySMB::SMB2::Packet::EchoResponse.new }

      it '#smb2_echo sends an Echo Request and returns a response' do
        allow(RubySMB::SMB2::Packet::EchoRequest).to receive(:new).and_return(echo_request)
        expect(smb2_client).to receive(:send_recv).with(echo_request).and_return(echo_response.to_binary_s)
        expect(smb2_client.smb2_echo).to eq echo_response
      end

      it 'raise an InvalidPacket exception when the response is not valid' do
        echo_response.smb2_header.command = RubySMB::SMB2::Commands::SESSION_SETUP
        allow(smb2_client).to receive(:send_recv).and_return(echo_response.to_binary_s)
        expect { smb2_client.smb2_echo }.to raise_error(RubySMB::Error::InvalidPacket)
      end
    end
  end

end

