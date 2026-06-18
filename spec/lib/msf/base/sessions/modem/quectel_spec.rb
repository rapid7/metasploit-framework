# frozen_string_literal: true

require 'spec_helper'
require 'msf/base/sessions/modem'
require 'msf/base/sessions/modem/quectel'
require 'timeout'

RSpec.describe Msf::Sessions::Modem::Quectel do
  subject(:session) { described_class.new(modem) }

  let(:serial) { double('serial', path: '/dev/ttyUSB0') }
  let(:modem) do
    double('QuectelModem', open_tcp_client_socket: nil, open_udp_socket: nil,
                           close: nil, serial: serial)
  end
  let(:spawned_threads) { [] }
  let(:thread_manager) do
    double('thread_manager').tap do |manager|
      allow(manager).to receive(:spawn) do |name, critical, *args, &block|
        thread = ::Thread.new(*args) do |*thread_args|
          ::Thread.current[:tm_name] = name
          ::Thread.current[:tm_crit] = critical
          block.call(*thread_args)
        end
        spawned_threads << thread
        thread
      end
    end
  end
  let(:framework) { double('framework', threads: thread_manager) }
  # Connection duck-type consumed by the channel/socket wrappers.
  let(:recv_queue) { Queue.new }
  let(:conn) do
    double('conn', send: nil).tap do |connection|
      allow(connection).to receive(:recv) { recv_queue.pop }
      allow(connection).to receive(:close) { recv_queue << nil }
    end
  end

  def params_double(peerhost:, peerport: 53, localhost: '0.0.0.0', localport: 0)
    double('params', proto: 'udp', server: false, peerhost: peerhost, peerhostname: peerhost,
                     peerport: peerport, localhost: localhost, localport: localport,
                     sslkeylogfile: nil, context: nil, v6: false)
  end

  before do
    @original_thread_factory_provider = Rex::ThreadFactory.class_variable_get(:@@provider)
    Rex::ThreadFactory.provider = thread_manager
    session.framework = framework
  end

  after do
    Rex::ThreadFactory.provider = @original_thread_factory_provider

    spawned_threads.each do |thread|
      thread.kill if thread.alive?
      thread.join
    end
  end

  describe 'identity' do
    it 'supports native UDP' do
      expect(session.supports_udp?).to be(true)
    end

    it 'has a Quectel description' do
      expect(session.desc).to eq('Quectel modem')
    end

    it 'populates info with the description' do
      expect(session.info).to eq('Quectel modem')
    end

    it 'returns the serial device path from tunnel_to_s' do
      expect(session.tunnel_to_s).to eq('/dev/ttyUSB0')
    end
  end

  describe '#create_tcp_client_channel' do
    let(:params) { params_double(peerhost: '192.0.2.10', peerport: 80) }

    it 'raises ConnectionError when the modem cannot open the connection' do
      allow(modem).to receive(:open_tcp_client_socket).and_return(nil)
      expect { session.send(:create_tcp_client_channel, params) }
        .to raise_error(::Rex::ConnectionError)
    end

    it 'returns the local socket end on success' do
      allow(modem).to receive(:open_tcp_client_socket).and_return(conn)
      sock = session.send(:create_tcp_client_channel, params)
      expect(sock).to respond_to(:syswrite)
      sock.channel.close
    end
  end

  describe '#create_tcp_server_channel' do
    it 'is not supported and raises ConnectionError' do
      params = params_double(peerhost: '0.0.0.0', peerport: 4444)
      expect { session.send(:create_tcp_server_channel, params) }
        .to raise_error(::Rex::ConnectionError)
    end
  end

  describe '#create_udp_channel' do
    # No bypass to the local comm is permitted: loopback/link-local destinations
    # must still be opened through the modem (or fail), never via Comm::Local.
    %w[127.0.0.1 ::1 169.254.1.1 fe80::1 8.8.8.8].each do |addr|
      it "opens #{addr} through the modem rather than bypassing to the local comm" do
        params = params_double(peerhost: addr)
        expect(::Rex::Socket::Comm::Local).not_to receive(:create)
        expect(modem).to receive(:open_udp_socket).with(addr, 53).and_return(conn)
        sock = session.send(:create_udp_channel, params)
        expect(sock).to be_a(Rex::Socket::Udp)
        sock.channel.close
      end
    end

    it 'returns a real UDP local socket end on success' do
      params = params_double(peerhost: '8.8.8.8')
      allow(modem).to receive(:open_udp_socket).with('8.8.8.8', 53).and_return(conn)
      sock = session.send(:create_udp_channel, params)
      expect(sock).to be_a(Rex::Socket::Udp)
      expect(sock).to respond_to(:sendto, :recvfrom)
      sock.channel.close
    end

    it 'raises ConnectionError (no local-comm fallback) when the modem refuses the UDP open' do
      params = params_double(peerhost: '8.8.8.8')
      allow(modem).to receive(:open_udp_socket).and_return(nil)
      expect(::Rex::Socket::Comm::Local).not_to receive(:create)
      expect { session.send(:create_udp_channel, params) }
        .to raise_error(::Rex::ConnectionError)
    end
  end

  describe '#cleanup' do
    it 'closes the underlying modem' do
      expect(modem).to receive(:close)
      session.cleanup
    end

    it 'closes the underlying modem when channel cleanup raises' do
      chan = double('channel')
      allow(chan).to receive(:cid).and_return(1)
      allow(chan).to receive(:close).and_raise(::RuntimeError, 'channel cleanup failed')
      session.add_channel(chan)

      expect(modem).to receive(:close)
      expect { session.cleanup }.to raise_error(::RuntimeError, 'channel cleanup failed')
    end
  end
end

RSpec.describe Msf::Sessions::Modem::Quectel::Connection do
  subject(:connection) { described_class.new(modem, 4) }

  let(:cfg) do
    {
      max_chunk_size: 1024,
      cmd_timeout: 1,
      prompt_timeout: 1,
      ack_timeout: 1
    }
  end
  let(:serial) { double('serial') }
  let(:modem) do
    double(
      'QuectelDriver',
      at_lock: Mutex.new,
      cfg: cfg,
      closed?: false,
      log_debug: nil,
      mutex: Mutex.new,
      pending_send_sid: nil,
      serial: serial
    )
  end

  before do
    allow(modem).to receive(:pending_send_sid=)
  end

  describe '#close' do
    it 'sends QICLOSE and releases the SID once' do
      expect(modem).to receive(:send_at).with('AT+QICLOSE=4,0', 1).once
      expect(modem).to receive(:release_id).with(4).once

      connection.close
      connection.close

      expect(connection).to be_closed
    end

    it 'does not send QICLOSE after a remote close has already released the SID' do
      expect(modem).to receive(:release_id).with(4).once
      expect(modem).not_to receive(:send_at)

      connection.mark_closed
      connection.close

      expect(connection.recv).to be_nil
    end
  end

  describe '#recv' do
    it 'returns nil without blocking after the close sentinel has been drained' do
      expect(modem).to receive(:release_id).with(4).once

      connection.mark_closed

      expect(connection.recv).to be_nil
      expect(::Timeout.timeout(0.1) { connection.recv }).to be_nil
    end
  end

  describe '#send' do
    it 'fails before QISEND when the connection is already remote-closed' do
      allow(modem).to receive(:release_id)
      expect(serial).not_to receive(:write)

      connection.mark_closed

      expect { connection.send('payload') }.to raise_error(IOError)
    end
  end
end

RSpec.describe Msf::Sessions::Modem::Quectel::Driver do
  subject(:driver) { described_class.allocate }

  let(:conn) { double('conn') }
  let(:health_thread) { instance_double(::Thread) }
  let(:reader_thread) { instance_double(::Thread) }
  let(:serial) { double('serial') }

  before do
    driver.instance_variable_set(:@closed, false)
    driver.instance_variable_set(:@conns, { 0 => conn })
    driver.instance_variable_set(:@health_stop, false)
    driver.instance_variable_set(:@health_thread, health_thread)
    driver.instance_variable_set(:@reader_stop, false)
    driver.instance_variable_set(:@reader_thread, reader_thread)
    driver.instance_variable_set(:@serial, serial)
  end

  describe '#close' do
    it 'closes the serial device and stops background threads' do
      expect(conn).to receive(:mark_closed)
      expect(serial).to receive(:close)

      expect(health_thread).to receive(:join).with(1)
      expect(health_thread).to receive(:alive?).and_return(true)
      expect(health_thread).to receive(:kill)
      expect(health_thread).to receive(:join).with(no_args)

      expect(reader_thread).to receive(:join).with(1)
      expect(reader_thread).to receive(:alive?).and_return(true)
      expect(reader_thread).to receive(:kill)
      expect(reader_thread).to receive(:join).with(no_args)

      driver.close

      expect(driver).to be_closed
      expect(driver.instance_variable_get(:@health_stop)).to be(true)
      expect(driver.instance_variable_get(:@reader_stop)).to be(true)
      expect(driver.instance_variable_get(:@conns)).to be_empty
    end

    it 'does nothing when already closed' do
      driver.instance_variable_set(:@closed, true)

      expect(conn).not_to receive(:mark_closed)
      expect(serial).not_to receive(:close)
      expect(health_thread).not_to receive(:join)
      expect(reader_thread).not_to receive(:join)

      driver.close
    end
  end

  describe '#handle_line' do
    before do
      driver.instance_variable_set(:@cfg, { modem_sockets: 12 })
      driver.instance_variable_set(:@cmd_mutex, Mutex.new)
      driver.instance_variable_set(:@pending_cmds, [])
      driver.instance_variable_set(:@id_mutex, Mutex.new)
      driver.instance_variable_set(:@free_ids, [])
      driver.instance_variable_set(:@conns, {})
      allow(driver).to receive(:log_debug)
    end

    it 'marks remote closed connections and releases their SID' do
      conn = Msf::Sessions::Modem::Quectel::Connection.new(driver, 2)
      driver.register_connection(2, conn)

      driver.send(:handle_line, '+QIURC: "closed",2')

      expect(conn).to be_closed
      expect(conn.recv).to be_nil
      expect(driver.connection_for_id(2)).to be_nil
      expect(driver.instance_variable_get(:@free_ids)).to include(2)
    end
  end
end
