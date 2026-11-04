require 'spec_helper'
require 'rex/io/stream_abstraction'
require 'rex/proto/ms_tds/channel'
require 'rex/socket/ssl_tcp'
require 'timeout'

RSpec.describe Rex::Proto::MsTds::Channel do
  let(:server) { TCPServer.new('127.0.0.1', 0) }
  let(:channel) { described_class.new('PeerHost' => '127.0.0.1', 'PeerPort' => server.addr[1]) }
  let(:peer) { server.accept }
  let(:relay) { channel.send(:monitor_thread) }

  before do
    channel
    peer
    relay.report_on_exception = false
  end

  after do
    # Wake both readers before joining, including when the example fails.
    [channel.lsock, channel.rsock, channel.sock].each do |socket|
      socket.shutdown(::Socket::SHUT_RDWR) unless socket.closed?
    end
    peer.close unless peer.closed?
    expect(relay.join(3)).to eq(relay)
    channel.lsock.close unless channel.lsock.closed?
    server.close
  end

  def expect_transport_closed
    expect(::IO.select([peer], nil, nil, 3)).not_to be_nil
    expect(peer.read_nonblock(1, exception: false)).to be_nil
    expect(relay.join(3)).to eq(relay)
    expect(channel.sock).to be_closed
    expect(channel.rsock).to be_closed
  end

  it 'relays data in both directions before the local stream is closed' do
    channel.lsock.write('request')
    expect(Timeout.timeout(3) { peer.read(7) }).to eq('request')
    peer.write('reply')
    expect(Timeout.timeout(3) { channel.lsock.read(5) }).to eq('reply')
    expect(channel.sock).not_to be_closed
    expect(relay).to be_alive
    channel.lsock.close
    expect_transport_closed
  end

  it 'closes the server connection and stops the relay when the local stream closes' do
    channel.lsock.close
    expect_transport_closed
  end

  it 'stops both relays when the peer closes first' do
    peer.close
    expect(relay.join(3)).to eq(relay)
    expect(channel.sock).to be_closed
    expect(channel.rsock).to be_closed
    expect(::IO.select([channel.lsock], nil, nil, 3)).not_to be_nil
    expect(channel.lsock.read_nonblock(1, exception: false)).to be_nil
  end

  it 'allows repeated shutdown callbacks after the relay exits' do
    channel.lsock.close
    expect_transport_closed
    2.times do
      expect { channel.close_write }.not_to raise_error
      expect { channel.send(:_exit_handler) }.not_to raise_error
    end
  end

  it 'closes the server connection when the local stream has the TLS wrapper' do
    ssl_socket = instance_double(OpenSSL::SSL::SSLSocket)
    allow(ssl_socket).to receive(:close)
    channel.lsock.extend(Rex::Socket::SslTcp)
    channel.lsock.sslsock = ssl_socket

    expect(channel.lsock.shutdown(::Socket::SHUT_RDWR)).to be_nil
    expect(channel.lsock).not_to be_closed
    channel.lsock.close

    expect(ssl_socket).to have_received(:close)
    expect_transport_closed
  end

  it 'handles the peer and local stream closing together' do
    closer = Thread.new { peer.close }
    channel.lsock.close
    closer.join
    expect(relay.join(3)).to eq(relay)
    expect(channel.sock).to be_closed
    expect(channel.rsock).to be_closed
  end
end
