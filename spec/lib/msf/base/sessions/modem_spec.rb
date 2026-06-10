# frozen_string_literal: true

require 'spec_helper'
require 'msf/base/sessions/modem'

RSpec.describe Msf::Sessions::Modem do
  subject(:session) { Msf::Sessions::Modem.new }

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

  # Minimal connection duck-type used by the channel/socket classes:
  #   recv      -> blocks until String data or nil EOF
  #   send(buf) -> bytes sent
  #   close
  let(:recv_queue) { Queue.new }
  let(:conn) do
    double('conn', send: nil).tap do |connection|
      allow(connection).to receive(:recv) { recv_queue.pop }
      allow(connection).to receive(:close) { recv_queue << nil }
    end
  end

  def params_double(proto:, server: false, peerhost: '192.0.2.1', peerport: 80,
                    localhost: '0.0.0.0', localport: 0)
    double('params', proto: proto, server: server, peerhost: peerhost, peerhostname: peerhost,
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

  def queue_pop(queue, timeout: 2)
    deadline = Time.now + timeout
    loop do
      return queue.pop(true)
    rescue ThreadError
      raise 'Timed out waiting for queue item' if Time.now >= deadline

      sleep 0.01
    end
  end

  describe 'session identity' do
    it 'reports the modem type' do
      expect(described_class.type).to eq('modem')
      expect(session.type).to eq('modem')
    end

    it 'reports a hardware platform and command arch' do
      expect(session.platform).to eq('hardware')
      expect(session.arch).to eq(ARCH_CMD)
    end

    it 'is non-interactive' do
      expect(session.interactive?).to be(false)
      expect(session.interacting).to be(false)
    end

    it 'does not support UDP at the base level' do
      expect(session.supports_udp?).to be(false)
    end

    it 'cannot clean up files' do
      expect(described_class.can_cleanup_files).to be(false)
    end
  end

  describe '#create dispatch' do
    it 'routes udp to create_udp_channel' do
      params = params_double(proto: 'udp')
      expect(session).to receive(:create_udp_channel).with(params).and_return(:udp_sock)
      expect(session.create(params)).to eq(:udp_sock)
    end

    it 'routes tcp client to create_tcp_client_channel' do
      params = params_double(proto: 'tcp', server: false)
      expect(session).to receive(:create_tcp_client_channel).with(params).and_return(:tcp_sock)
      expect(session.create(params)).to eq(:tcp_sock)
    end

    it 'routes tcp server to create_tcp_server_channel' do
      params = params_double(proto: 'tcp', server: true)
      expect(session).to receive(:create_tcp_server_channel).with(params).and_return(:srv_sock)
      expect(session.create(params)).to eq(:srv_sock)
    end

    it 'raises ConnectionError on an unsupported protocol' do
      params = params_double(proto: 'sctp')
      expect { session.create(params) }.to raise_error(::Rex::ConnectionError)
    end
  end

  describe 'base subclass hooks' do
    it 'raises NotImplementedError for tcp client channels' do
      expect { session.send(:create_tcp_client_channel, params_double(proto: 'tcp')) }
        .to raise_error(NotImplementedError)
    end

    it 'raises NotImplementedError for tcp server channels' do
      expect { session.send(:create_tcp_server_channel, params_double(proto: 'tcp', server: true)) }
        .to raise_error(NotImplementedError)
    end

    it 'raises NotImplementedError for udp channels' do
      expect { session.send(:create_udp_channel, params_double(proto: 'udp')) }
        .to raise_error(NotImplementedError)
    end
  end

  describe '#cleanup' do
    it 'closes every open channel' do
      chan = double('channel', close: nil)
      allow(chan).to receive(:cid).and_return(1)
      session.add_channel(chan)
      expect(chan).to receive(:close)
      session.cleanup
    end

    it 'allows channels to remove themselves while cleaning up' do
      first_channel = double('first_channel')
      second_channel = double('second_channel')
      allow(first_channel).to receive(:cid).and_return(1)
      allow(second_channel).to receive(:cid).and_return(2)
      allow(first_channel).to receive(:close) { session.remove_channel(1) }
      allow(second_channel).to receive(:close) { session.remove_channel(2) }

      session.add_channel(first_channel)
      session.add_channel(second_channel)

      expect { session.cleanup }.not_to raise_error
      expect(session.channels).to be_empty
    end
  end

  describe Msf::Sessions::Modem::UdpChannel do
    let(:params) { params_double(proto: 'udp', peerhost: '8.8.8.8', peerport: 53) }

    it 'spawns the reader through the framework thread manager' do
      chan = described_class.new(session, 1, conn, params)

      expect(thread_manager).to have_received(:spawn).with('ModemUdpChannelReader', false)
      chan.close
    end

    it 'hands back a real Rex::Socket::Udp lsock reporting the udp type' do
      chan = described_class.new(session, 1, conn, params)
      expect(chan.lsock).to be_a(Rex::Socket::Udp)
      expect(chan.lsock.type?).to eq('udp')
      chan.close
    end

    it 'forwards lsock writes to conn.send and returns the length' do
      chan = described_class.new(session, 2, conn, params)
      expect(conn).to receive(:send).with('query')
      expect(chan.lsock.write('query')).to eq(5)
      chan.close
    end

    it 'forwards lsock sendto to conn.send' do
      chan = described_class.new(session, 3, conn, params)
      expect(conn).to receive(:send).with('query')
      chan.lsock.sendto('query', '8.8.8.8', 53)
      chan.close
    end

    it 'drains an inbound datagram into the lsock as [data, host, port]' do
      recv_queue << 'response'
      recv_queue << nil
      chan = described_class.new(session, 4, conn, params)

      data, host, port = chan.lsock.recvfrom(65535, 2)
      expect(data).to eq('response')
      expect(host).to eq('8.8.8.8')
      expect(port).to eq(53)
      chan.close
    end

    it 'reads the synthetic sockaddr with its full length' do
      recv_queue << 'response'
      recv_queue << nil
      chan = described_class.new(session, 4, conn, params)

      data, host, port = chan.lsock.recvfrom(1, 2)
      expect(data).to eq('r')
      expect(host).to eq('8.8.8.8')
      expect(port).to eq(53)
      chan.close
    end

    it 'closes the connection once and is idempotent' do
      chan = described_class.new(session, 5, conn, params)
      expect(conn).to receive(:close).once do
        recv_queue << nil
      end
      chan.close
      chan.close
      expect(chan.closed?).to be(true)
    end

    it 'closes the connection when the framework closes the local socket' do
      closed = Queue.new
      allow(conn).to receive(:close) do
        recv_queue << nil
        closed << true
      end
      chan = described_class.new(session, 6, conn, params)

      chan.lsock.close

      expect(queue_pop(closed)).to be(true)
      expect(conn).to have_received(:close).once
      expect(chan.closed?).to be(true)
      expect(session.channels).to be_empty
    end

    it 'marks the channel remote-closed when the connection reports closed' do
      recv_queue << nil
      closed = Queue.new
      allow(conn).to receive(:close) do
        recv_queue << nil
        closed << true
      end
      chan = described_class.new(session, 7, conn, params)

      expect(queue_pop(closed)).to be(true)
      expect(conn).to have_received(:close).once
      expect(chan.remote_closed?).to be(true)
      expect { chan.lsock.write('query') }.to raise_error(IOError)
      chan.close
    end
  end

  describe Msf::Sessions::Modem::TcpClientChannel do
    let(:params) { params_double(proto: 'tcp') }

    it 'spawns the reader through the framework thread manager' do
      chan = described_class.new(session, 1, conn, params)

      expect(thread_manager).to have_received(:spawn).with('ModemTcpClientChannelReader', false)
      chan.close
    end

    it 'relays lsock writes to conn.send' do
      sent = Queue.new
      allow(conn).to receive(:send) { |data| sent << data }
      chan = described_class.new(session, 1, conn, params)

      expect(chan.lsock.write('payload')).to eq(7)
      expect(queue_pop(sent)).to eq('payload')
      chan.close
    end

    it 'forwards writes to conn.send and returns the length' do
      chan = described_class.new(session, 2, conn, params)
      expect(conn).to receive(:send).with('payload')
      expect(chan.write('payload')).to eq(7)
      chan.close
    end

    it 'drains incoming data from conn into the readable socket' do
      recv_queue << 'hello'
      recv_queue << nil
      chan = described_class.new(session, 3, conn, params)

      data = String.new
      deadline = Time.now + 2
      while Time.now < deadline
        ready = IO.select([chan.lsock], nil, nil, 0.1)
        next unless ready

        begin
          data << chan.lsock.recv(64)
        rescue StandardError
          break
        end
        break unless data.empty?
      end

      expect(data).to eq('hello')
      chan.close
    end

    it 'reports closed after #close' do
      chan = described_class.new(session, 4, conn, params)
      expect(chan.closed?).to be(false)
      chan.close
      expect(chan.closed?).to be(true)
    end

    it 'closes the connection when the framework closes the local socket' do
      closed = Queue.new
      allow(conn).to receive(:close) do
        recv_queue << nil
        closed << true
      end
      chan = described_class.new(session, 5, conn, params)

      chan.lsock.close

      expect(queue_pop(closed)).to be(true)
      expect(conn).to have_received(:close).once
      expect(chan.closed?).to be(true)
      expect(session.channels).to be_empty
    end

    it 'signals EOF and rejects writes when the connection reports closed' do
      recv_queue << 'hello'
      recv_queue << nil
      closed = Queue.new
      allow(conn).to receive(:close) do
        recv_queue << nil
        closed << true
      end
      chan = described_class.new(session, 6, conn, params)

      expect(queue_pop(closed)).to be(true)
      expect(conn).to have_received(:close).once
      expect(chan.remote_closed?).to be(true)
      expect(chan.lsock.read(5)).to eq('hello')
      expect { chan.write('again') }.to raise_error(IOError)
      chan.close
    end
  end
end
