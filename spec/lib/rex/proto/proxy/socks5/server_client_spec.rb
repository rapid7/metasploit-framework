# -*- coding:binary -*-

RSpec.describe Rex::Proto::Proxy::Socks5::ServerClient do
  let(:relay_manager) { instance_double(Rex::IO::RelayManager) }
  let(:server) do
    instance_double(
      Rex::Proto::Proxy::Socks5::Server,
      opts: {},
      add_client: nil,
      remove_client: nil,
      relay_manager: relay_manager
    )
  end
  let(:lsock) { instance_double('Rex::Socket::Tcp') }
  let(:rsock) { instance_double('Rex::Socket::Tcp') }

  subject(:client) { described_class.new(server, lsock) }

  before do
    allow(lsock).to receive(:close)
    allow(rsock).to receive(:close)
    client.instance_variable_set(:@rsock, rsock)
  end

  describe '#setup_tcp_relay' do
    before do
      allow(relay_manager).to receive(:add_relay)
    end

    it 'registers a relay from rsock to lsock' do
      expect(relay_manager).to receive(:add_relay).with(
        rsock,
        sink: lsock,
        name: 'SOCKS5ProxyRelay-Remote',
        on_exit: anything
      )
      client.send(:setup_tcp_relay)
    end

    it 'registers a relay from lsock to rsock' do
      expect(relay_manager).to receive(:add_relay).with(
        lsock,
        sink: rsock,
        name: 'SOCKS5ProxyRelay-Local',
        on_exit: anything
      )
      client.send(:setup_tcp_relay)
    end

    it 'passes a callable stop callback for each relay' do
      on_exit_callbacks = []
      allow(relay_manager).to receive(:add_relay) do |_sock, **kwargs|
        on_exit_callbacks << kwargs[:on_exit]
      end

      client.send(:setup_tcp_relay)

      expect(on_exit_callbacks.size).to eq(2)
      on_exit_callbacks.each { |cb| expect(cb).to respond_to(:call) }
    end

    it 'passes the client #stop method as the on_exit callback' do
      on_exit_callbacks = []
      allow(relay_manager).to receive(:add_relay) do |_sock, **kwargs|
        on_exit_callbacks << kwargs[:on_exit]
      end

      client.send(:setup_tcp_relay)

      on_exit_callbacks.each do |cb|
        expect(cb).to eq(client.method(:stop))
      end
    end
  end

  describe '#stop' do
    # Use a thread double so join doesn't actually block.
    let(:mock_thread) do
      thread = instance_double(Thread)
      allow(thread).to receive(:join)
      thread
    end

    before do
      client.instance_variable_set(:@client_thread, mock_thread)
    end

    it 'closes the local socket' do
      expect(lsock).to receive(:close)
      client.stop
    end

    it 'closes the remote socket' do
      expect(rsock).to receive(:close)
      client.stop
    end

    it 'removes itself from the server' do
      expect(server).to receive(:remove_client).with(client)
      client.stop
    end

    it 'joins the client thread when called from an external thread' do
      expect(mock_thread).to receive(:join)
      client.stop
    end

    it 'does not deadlock when called from within the client thread' do
      completed = false

      # Use a real thread and have it set @client_thread to itself before calling stop
      client_thread = Thread.new do
        client.instance_variable_set(:@client_thread, Thread.current)
        client.stop
        completed = true
      end

      result = client_thread.join(2)
      expect(result).not_to be_nil, 'stop deadlocked when called from the client thread'
      expect(completed).to be(true)
    end

    it 'is idempotent - a second call is a no-op' do
      client.stop
      expect { client.stop }.not_to raise_error
      expect(lsock).to have_received(:close).once
    end

    it 'sets @closed so subsequent calls are skipped' do
      client.stop
      expect(client.instance_variable_get(:@closed)).to be(true)
    end
  end
end
