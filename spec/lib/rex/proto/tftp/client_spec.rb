# frozen_string_literal: true

require 'spec_helper'
require 'tempfile'

RSpec.describe Rex::Proto::TFTP::Client do
  subject(:client) { described_class.allocate }

  let(:sock) { instance_double(Rex::Socket::Udp) }
  let(:host) { '192.0.2.10' }
  let(:constants) { Rex::Proto::TFTP::Constants }

  describe 'request methods' do
    before do
      client.threads = []
      client.peer_host = host
      client.peer_port = 69
      client.local_host = '127.0.0.1'
      client.local_port = 0
      client.context = {}
      allow(client).to receive(:start_server_socket)
      allow(Rex::Socket::Udp).to receive(:create).and_return(sock)
      allow(Rex::ThreadFactory).to receive(:spawn)
    end

    describe '#send_read_request' do
      before { allow(client).to receive(:rrq_packet).and_return('rrq') }

      it 'sends the RRQ with flags 0 to the peer host and port' do
        expect(sock).to receive(:send).with('rrq', 0, host, 69)
        client.send_read_request
      end

      it 'does not use the deprecated sendto' do
        allow(sock).to receive(:send)
        expect(sock).not_to receive(:sendto)
        client.send_read_request
      end
    end

    describe '#send_write_request' do
      before { allow(client).to receive(:wrq_packet).and_return('wrq') }

      it 'sends the WRQ with flags 0 to the peer host and port' do
        expect(sock).to receive(:send).with('wrq', 0, host, 69)
        client.send_write_request
      end

      it 'does not use the deprecated sendto' do
        allow(sock).to receive(:send)
        expect(sock).not_to receive(:sendto)
        client.send_write_request
      end
    end
  end

  describe '#write_and_ack_data' do
    let(:tempfile) { instance_double(Tempfile, write: nil, flush: nil) }

    before do
      client.server_sock = sock
      client.recv_tempfile = tempfile
    end

    it 'acks the block with flags 0 to the given host and port' do
      expected_ack = [constants::OpAck, 3].pack('nn')
      expect(sock).to receive(:send).with(expected_ack, 0, host, 4444).and_return(4)
      client.__send__(:write_and_ack_data, 'data', 3, host, 4444)
    end

    it 'does not use the deprecated sendto' do
      allow(sock).to receive(:send).and_return(4)
      expect(sock).not_to receive(:sendto)
      client.__send__(:write_and_ack_data, 'data', 3, host, 4444)
    end
  end

  describe '#send_data' do
    let(:data_packet) { [constants::OpData, 1, 'abc'].pack('nnA*') }
    let(:ack_response) { ['ack', ['AF_INET', 4444, 'localhost', host]] }

    before do
      client.server_sock = sock
      allow(client).to receive(:blockify_file_or_data).and_return(['abc'])
      allow(client).to receive(:parse_tftp_response).and_return([4, 1, nil])
      allow(sock).to receive(:timed_recvfrom).and_return(ack_response)
    end

    it 'sends the data block with flags 0 to the given host and port' do
      expect(sock).to receive(:send).with(data_packet, 0, host, 4444).and_return(data_packet.length)
      client.send_data(host, 4444)
    end

    it 'retries the same block when send returns 0' do
      expect(sock).to receive(:send).with(data_packet, 0, host, 4444).twice.and_return(0, data_packet.length)
      client.send_data(host, 4444)
    end

    it 'does not use the deprecated sendto' do
      allow(sock).to receive(:send).and_return(data_packet.length)
      expect(sock).not_to receive(:sendto)
      client.send_data(host, 4444)
    end
  end
end
