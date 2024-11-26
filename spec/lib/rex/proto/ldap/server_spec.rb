# frozen_string_literal: true
require 'rex/text'

RSpec.describe Rex::Proto::LDAP::Server do

  subject(:ldif) { nil }

  subject(:auth_provider) do
    Rex::Proto::LDAP::Auth.new(nil, nil, nil, nil, nil)
  end

  subject(:server) do
    described_class.new('0.0.0.0', 40000, true, true, ldif, nil, auth_provider)
  end

  let(:response) {}

  let(:tcp_server_socket) do
    double :tcp_server_socket,
          start: nil,
          :on_client_connect_proc= => nil,
          :on_client_data_proc= => nil,
          closed?: false,
          close: nil
  end

  let(:udp_server_socket) do
    double :udp_server_socket,
           start: nil,
           :on_client_connect_proc= => nil,
           :on_client_data_proc= => nil,
           closed?: false,
           close: nil
  end

  let(:udp_monitor_thread) do
    instance_double ::Thread, alive?: true
  end

  before do
    allow(Rex::Socket::TcpServer).to receive(:create).and_return(tcp_server_socket)
    allow(Rex::Socket::Udp).to receive(:create).and_return(udp_server_socket)
    allow(Rex::ThreadFactory).to receive(:spawn).with('UDPLDAPServerListener', false).and_return(udp_monitor_thread)
    server.processed_pdu_handler(Net::LDAP::PDU::BindRequest) do |processed_data|
      processed_data = 'Processed Data'
    end
  end

  context 'initialize' do
    it 'sets the server options correctly' do
      expect(server.serve_udp).to eq(true)
      expect(server.serve_tcp).to eq(true)
      expect(server.sock_options).to include('LocalHost' => '0.0.0.0', 'LocalPort' => 40000, 'Comm' => nil)
      expect(server.ldif).to eq(ldif)
      expect(server.instance_variable_get(:@auth_provider)).to eq(auth_provider)
      expect(server.instance_variable_get(:@auth_provider)).to be_a(Rex::Proto::LDAP::Auth)
    end
  end

  describe '#running?' do
    context 'when the server is not running' do
      it 'returns false' do
        expect(server.running?).to be_nil
      end
    end

    context 'when the server is running' do
      before { server.start }

      it 'returns true' do
        expect(server.running?).not_to be_nil
      end

      after { server.stop }
    end
  end

  describe '#start' do
    context 'start server with the provided options' do
      before { server.start }

      it 'starts the UDP server if serve_udp is true' do
        if server.serve_udp
          expect(server.udp_sock).to be udp_server_socket
          expect(server.running?).to be true
        end
      end

      it 'starts the TCP server if serve_tcp is true' do
        if server.serve_tcp
          expect(server.tcp_sock).to be tcp_server_socket
          expect(server.running?).to be true
        end
      end

      after { server.stop }
    end
  end

  describe '#stop' do
    before { server.start }

    it 'stops the server when running' do
      server.stop
      expect(server.running?).to be nil
    end
  end

  describe '#dispatch_request' do
    it 'calls dispatch_request_proc if it is set' do
      client = double('client')
      allow(client).to receive(:peerhost) { '1.1.1.1' }
      allow(client).to receive(:peerport) { '389' }
      allow(client).to receive(:write).with(response)
      allow(client).to receive(:close)

      block_called = false
      server.dispatch_request_proc = proc { block_called = true }
      server.dispatch_request(client, 'LDAP request data')
      expect(block_called).to be true
    end

    it 'calls default_dispatch_request if dispatch_request_proc is not set' do
      client = double('client')
      allow(client).to receive(:peerhost) { '1.1.1.1' }
      allow(client).to receive(:peerport) { '389' }
      allow(client).to receive(:write).with(any_args)
      allow(client).to receive(:close)

      expect { server.dispatch_request(client, String.new("02\x02\x01\x01`-\x02\x01\x03\x04\"cn=user,dc=example,dc=com\x80\x04kali").force_encoding('ASCII-8BIT')) }.not_to raise_error
    end
  end

  describe '#default_dispatch_request' do
    it 'returns nil for empty request data' do
      client = double('client')
      allow(client).to receive(:peerhost) { '1.1.1.1' }
      allow(client).to receive(:peerport) { '389' }
      allow(client).to receive(:write).with(any_args)
      allow(client).to receive(:close)
      data = ''
      expect { server.default_dispatch_request(client, data) }.not_to raise_error
    end
  end

  describe '#encode_ldap_response' do
    it 'encodes an LDAP response correctly' do
      msgid = 1
      code = Net::LDAP::ResultCodeSuccess
      dn = ''
      msg = Net::LDAP::ResultStrings[Net::LDAP::ResultCodeSuccess]
      tag = Net::LDAP::PDU::BindResult
      context_data = nil
      context_code = nil

      response = server.encode_ldap_response(msgid, code, dn, msg, tag, context_data, context_code)
      expect(response).to be_a(String)
    end
  end

  describe '#search_result' do
    context 'when searching with no LDIF data' do
      it 'returns a random search result' do
        result = server.search_result(nil, 1)

        expect(result).to be_nil
      end
    end
  end

  describe '#processed_pdu_handler' do
    it 'sets the processed_pdu_handler correctly' do

      expect(server.instance_variable_get(:@pdu_process)[Net::LDAP::PDU::BindRequest]).to be_a(Proc)
      expect((server.instance_variable_get(:@pdu_process)[Net::LDAP::PDU::BindRequest]).call({})).to eq('Processed Data')
    end
  end

  describe '#suitable_response' do
    it 'returns the appropriate response type for a given request type' do
      expect(server.suitable_response(Net::LDAP::PDU::BindRequest)).to eq(Net::LDAP::PDU::BindResult)
      expect(server.suitable_response(Net::LDAP::PDU::SearchRequest)).to eq(Net::LDAP::PDU::SearchResult)
    end
  end
end
