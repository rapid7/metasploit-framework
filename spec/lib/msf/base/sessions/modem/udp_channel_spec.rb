require 'spec_helper'
require 'msf/base/sessions/modem'

RSpec.describe Msf::Sessions::Modem::UdpChannel do
  subject(:channel) { described_class.new(session, 1, conn, params) }

  let(:params) { Rex::Socket::Parameters.new('PeerHost' => '192.0.2.1', 'PeerPort' => 53, 'Proto' => 'udp') }
  let(:thread_manager) { double('thread_manager') }
  let(:framework) { double('framework', threads: thread_manager) }
  let(:session) { double('session', framework: framework, add_channel: nil, remove_channel: nil) }
  let(:recv_queue) { Queue.new }
  let(:conn) do
    double('conn').tap do |connection|
      allow(connection).to receive(:recv) { recv_queue.pop }
      allow(connection).to receive(:close) { recv_queue << nil }
    end
  end

  before do
    allow(thread_manager).to receive(:spawn) do |_name, _critical, &block|
      Thread.new(&block)
    end
  end

  after do
    channel.close
  end

  it 'returns the payload and peer while the producer is paused after writing the payload' do
    written = Queue.new
    resume = Queue.new
    allow(channel.rsock).to receive(:syswrite).and_wrap_original do |original, data|
      result = original.call(data)
      written << true
      resume.pop
      result
    end
    recv_queue << 'response'
    expect(written.pop(timeout: 2)).to be(true)
    expect(IO.select([channel.lsock], nil, nil, 2)).not_to be_nil

    expect(channel.lsock.recvfrom_nonblock(1)).to eq(
      ['r', Rex::Socket.to_sockaddr(params.peerhost, params.peerport)]
    )
  ensure
    resume << true
  end

  it 'raises a readable-wait error when no datagram is available' do
    expect { channel.lsock.recvfrom_nonblock(65535) }.to raise_error(IO::WaitReadable)
  end

  it 'keeps peeked data available with the same peer address' do
    recv_queue << 'response'
    expect(IO.select([channel.lsock], nil, nil, 2)).not_to be_nil
    expected = ['response', Rex::Socket.to_sockaddr(params.peerhost, params.peerport)]

    expect(channel.lsock.recvfrom_nonblock(65535, Socket::MSG_PEEK)).to eq(expected)
    expect(channel.lsock.recvfrom_nonblock(65535)).to eq(expected)
    expect { channel.lsock.recvfrom_nonblock(65535) }.to raise_error(IO::WaitReadable)
  end

  it 'preserves datagram boundaries and peer addresses after a truncated read' do
    recv_queue << 'first'
    recv_queue << 'second'
    address = ['AF_INET', 53, '192.0.2.1', '192.0.2.1']

    expect(channel.lsock.timed_recvfrom(1, 2)).to eq(['f', address])
    expect(channel.lsock.timed_recvfrom(65535, 2)).to eq(['second', address])
    expect { channel.lsock.recvfrom_nonblock(65535) }.to raise_error(IO::WaitReadable)
  end
end
