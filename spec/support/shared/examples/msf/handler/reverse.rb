RSpec.shared_examples_for 'a reverse handler listener' do
  subject(:handler) do
    klass = Class.new(Msf::Payload)
    klass.include described_class
    klass.new
  end

  let(:listener_socket) { instance_double(socket_factory) }
  let(:resolved_address) { '192.0.2.10' }
  let(:fallback_address) { '0.0.0.0' }
  let(:datastore) do
    {
      'LHOST' => 'callback.example',
      'LPORT' => 4444
    }
  end

  before do
    datastore.each { |name, value| handler.datastore[name] = value }
    allow(Rex::Socket).to receive(:resolv_nbo).and_call_original
    allow(Rex::Socket).to receive(:resolv_nbo).with(datastore['LHOST']).and_return(IPAddr.new(resolved_address).hton)
  end

  describe '#setup_handler' do
    it 'stops after successfully binding to the resolved LHOST' do
      expect(socket_factory).to receive(:create)
        .with(hash_including('LocalHost' => resolved_address, 'LocalPort' => 4444))
        .once.and_return(listener_socket)

      handler.setup_handler

      expect(handler.send(:listener_sock)).to equal(listener_socket)
    end

    it 'tries the IPv4 wildcard after the preferred address fails to bind' do
      expect(socket_factory).to receive(:create)
        .with(hash_including('LocalHost' => resolved_address))
        .ordered.and_raise(Rex::BindFailed.new(resolved_address, 4444))
      expect(socket_factory).to receive(:create)
        .with(hash_including('LocalHost' => fallback_address))
        .ordered.and_return(listener_socket)

      handler.setup_handler

      expect(handler.send(:listener_sock)).to equal(listener_socket)
    end

    it 'raises the final bind error when both addresses fail' do
      final_error = Rex::BindFailed.new(fallback_address, 4444)
      expect(socket_factory).to receive(:create)
        .with(hash_including('LocalHost' => resolved_address))
        .ordered.and_raise(Rex::BindFailed.new(resolved_address, 4444))
      expect(socket_factory).to receive(:create)
        .with(hash_including('LocalHost' => fallback_address))
        .ordered.and_raise(final_error)

      expect { handler.setup_handler }.to raise_error(final_error)
    end

    context 'when LHOST resolves to IPv6' do
      let(:resolved_address) { '2001:db8::10' }
      let(:fallback_address) { '::0' }

      it 'tries the IPv6 wildcard after the preferred address fails to bind' do
        expect(socket_factory).to receive(:create)
          .with(hash_including('LocalHost' => resolved_address))
          .ordered.and_raise(Rex::BindFailed.new(resolved_address, 4444))
        expect(socket_factory).to receive(:create)
          .with(hash_including('LocalHost' => fallback_address))
          .ordered.and_return(listener_socket)

        handler.setup_handler

        expect(handler.send(:listener_sock)).to equal(listener_socket)
      end
    end

    context 'when LHOST cannot be resolved' do
      before do
        allow(Rex::Socket).to receive(:resolv_nbo).with(datastore['LHOST']).and_raise(SocketError)
      end

      it 'binds only to the IPv4 wildcard' do
        expect(socket_factory).to receive(:create)
          .with(hash_including('LocalHost' => '0.0.0.0'))
          .once.and_return(listener_socket)

        handler.setup_handler
      end
    end

    context 'when an explicit bind address is configured' do
      let(:datastore) do
        super().merge(
          'LHOST' => 'callback.invalid',
          'ReverseListenerBindAddress' => '192.0.2.20'
        )
      end

      it 'binds only to the configured address without resolving LHOST' do
        expect(Rex::Socket).not_to receive(:resolv_nbo).with('callback.invalid')
        expect(socket_factory).to receive(:create)
          .with(hash_including('LocalHost' => '192.0.2.20'))
          .once.and_return(listener_socket)

        handler.setup_handler
      end

      it 'raises the bind error without trying a wildcard address' do
        bind_error = Rex::BindFailed.new('192.0.2.20', 4444)
        expect(socket_factory).to receive(:create)
          .with(hash_including('LocalHost' => '192.0.2.20'))
          .once.and_raise(bind_error)

        expect { handler.setup_handler }.to raise_error(bind_error)
      end
    end
  end
end
