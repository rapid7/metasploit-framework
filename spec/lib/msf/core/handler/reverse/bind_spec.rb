require 'spec_helper'

RSpec.describe Msf::Handler::Reverse::Bind do
  let(:handler) do
    Class.new do
      include Msf::Handler::Reverse::Bind

      attr_accessor :datastore

      def print_warning(message)
        @warning = message
      end

      attr_reader :warning
    end.new
  end

  before do
    handler.datastore = {
      'LHOST' => '127.0.0.1',
      'ReverseListenerBindAddress' => ''
    }
  end

  describe '#is_loopback_address?' do
    it 'identifies IPv4 loopback addresses' do
      expect(handler.is_loopback_address?('127.0.0.1')).to be(true)
    end

    it 'identifies IPv6 loopback addresses' do
      expect(handler.is_loopback_address?('::1')).to be(true)
    end

    it 'does not identify normal addresses as loopback' do
      expect(handler.is_loopback_address?('192.168.1.10')).to be(false)
    end
  end

  describe '#bind_addresses' do
    context 'when ReverseListenerBindAddress is set' do
      before do
        handler.datastore['ReverseListenerBindAddress'] = '192.168.1.10'
      end

      it 'returns the configured bind address' do
        expect(handler.bind_addresses).to eq(['192.168.1.10'])
      end
    end

    context 'when LHOST resolves' do
      before do
        allow(Rex::Socket).to receive(:resolv_nbo).with('192.168.1.10').and_return(
          Rex::Socket.addr_aton('192.168.1.10')
        )
      end

      it 'returns the resolved address and IPv4 any address' do
        handler.datastore['LHOST'] = '192.168.1.10'

        expect(handler.bind_addresses).to eq(['192.168.1.10', '0.0.0.0'])
      end
    end

    context 'when LHOST cannot be resolved' do
      before do
        allow(Rex::Socket).to receive(:resolv_nbo).and_raise(SocketError)
      end

      it 'falls back to 0.0.0.0' do
        expect(handler.bind_addresses).to eq(['0.0.0.0'])
      end

      it 'prints a warning' do
        handler.bind_addresses

        expect(handler.warning).to include('is not locally resolvable')
      end
    end

    context 'when LHOST is a loopback address' do
      before do
        allow(Rex::Socket).to receive(:resolv_nbo).with('127.0.0.1').and_return(
          Rex::Socket.addr_aton('127.0.0.1')
        )
      end

      it 'prints a loopback warning' do
        handler.bind_addresses

        expect(handler.warning).to include('binding to a loopback address')
      end
    end
  end
end
