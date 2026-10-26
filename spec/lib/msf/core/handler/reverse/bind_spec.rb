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

    it 'identifies other addresses in the IPv4 loopback range' do
      expect(handler.is_loopback_address?('127.42.0.10')).to be(true)
    end

    it 'identifies IPv6 loopback addresses' do
      expect(handler.is_loopback_address?('::1')).to be(true)
    end

    it 'does not identify normal addresses as loopback' do
      expect(handler.is_loopback_address?('192.0.2.10')).to be(false)
    end

    it 'does not identify normal IPv6 addresses as loopback' do
      expect(handler.is_loopback_address?('2001:db8::10')).to be(false)
    end

    it 'returns false for an invalid address' do
      expect(handler.is_loopback_address?('not-an-address')).to be(false)
    end

    it 'returns false for a missing address' do
      expect(handler.is_loopback_address?(nil)).to be(false)
    end
  end

  describe '#bind_addresses' do
    context 'when ReverseListenerBindAddress is set' do
      let(:bind_address) { '192.0.2.20' }

      before do
        handler.datastore['ReverseListenerBindAddress'] = bind_address
      end

      it 'returns the configured bind address' do
        expect(handler.bind_addresses).to eq(['192.0.2.20'])
      end

      it 'does not resolve LHOST' do
        handler.datastore['LHOST'] = 'callback.invalid'
        allow(Rex::Socket).to receive(:resolv_nbo).and_call_original
        expect(Rex::Socket).not_to receive(:resolv_nbo).with('callback.invalid')

        handler.bind_addresses
      end

      context 'with an IPv6 address' do
        let(:bind_address) { '2001:db8::20' }

        it 'returns only the configured IPv6 address' do
          expect(handler.bind_addresses).to eq(['2001:db8::20'])
        end
      end

      context 'with an IPv4 wildcard' do
        let(:bind_address) { '0.0.0.0' }

        it 'returns only the IPv4 wildcard' do
          expect(handler.bind_addresses).to eq(['0.0.0.0'])
        end
      end

      context 'with a compressed IPv6 wildcard' do
        let(:bind_address) { '::' }

        it 'normalizes the IPv6 wildcard' do
          expect(handler.bind_addresses).to eq(['::0'])
        end
      end

      context 'with an already normalized IPv6 wildcard' do
        let(:bind_address) { '::0' }

        it 'preserves the IPv6 wildcard' do
          expect(handler.bind_addresses).to eq(['::0'])
        end
      end

      context 'with an expanded IPv6 wildcard' do
        let(:bind_address) { '0:0:0:0:0:0:0:0' }

        it 'normalizes the IPv6 wildcard' do
          expect(handler.bind_addresses).to eq(['::0'])
        end
      end

      context 'with a loopback address' do
        let(:bind_address) { '127.0.0.1' }

        it 'does not warn about an explicitly selected loopback address' do
          handler.bind_addresses

          expect(handler.warning).to be_nil
        end
      end
    end

    context 'when LHOST resolves' do
      let(:resolved_address) { '192.0.2.10' }

      before do
        handler.datastore['LHOST'] = 'callback.example'
        allow(Rex::Socket).to receive(:resolv_nbo).with('callback.example').and_return(
          IPAddr.new(resolved_address).hton
        )
      end

      it 'returns the resolved address and IPv4 any address' do
        expect(handler.bind_addresses).to eq(['192.0.2.10', '0.0.0.0'])
      end

      it 'does not warn about a non-loopback address' do
        handler.bind_addresses

        expect(handler.warning).to be_nil
      end

      context 'when ReverseListenerBindAddress is nil' do
        before do
          handler.datastore['ReverseListenerBindAddress'] = nil
        end

        it 'returns the resolved address and IPv4 any address' do
          expect(handler.bind_addresses).to eq(['192.0.2.10', '0.0.0.0'])
        end
      end

      context 'with an IPv6 address' do
        let(:resolved_address) { '2001:db8::10' }

        it 'returns the resolved address and IPv6 any address' do
          expect(handler.bind_addresses).to eq(['2001:db8::10', '::0'])
        end
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

      context 'with an IPv6 loopback address' do
        before do
          handler.datastore['LHOST'] = '::1'
          allow(Rex::Socket).to receive(:resolv_nbo).with('::1').and_return(IPAddr.new('::1').hton)
        end

        it 'prints an IPv6 loopback warning' do
          handler.bind_addresses

          expect(handler.warning).to include('binding to a loopback address by setting LHOST to ::1')
        end
      end
    end
  end
end
