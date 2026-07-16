lib = File.join(Msf::Config.install_root, "test", "lib")
$LOAD_PATH.push(lib) unless $LOAD_PATH.include?(lib)
require 'module_test'

class MetasploitModule < Msf::Post

  include Msf::Exploit::Retry
  include Msf::ModuleTest::PostTest

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Socket Channel Tests',
        'Description' => %q{
          This module will test socket channels. The LHOST and RHOST options must be set when Metasploit and the
          Meterpreter instance are not on the same host. It's important that there is no firewall or NAT in place.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'Spencer McIntyre' ],
        'Platform' => [ 'linux', 'osx', 'windows' ],
        'SessionTypes' => [ 'shell', 'meterpreter' ] # SSH sessions are reported as 'shell'
      )
    )

    register_options(
      [
        OptAddressLocal.new('LHOST', [true, 'The local IP address to use for binding.', '127.0.0.1']),
        OptAddress.new('RHOST', [true, 'The remote IP address to use for binding.', '127.0.0.1']),
        # HTTP polling payloads have inherent latency (backoff ramp + HTTP round-trip) even
        # after the backoff resets to 0 after each response, so use a generous CI timeout.
        # TCP payloads could use a much lower value but 60s is cheap headroom for both.
        OptInt.new('TIMEOUT', [true, 'The timeout in seconds to use when waiting for socket operations.', ENV['CI'] ? 60 : 20]),
      ], self.class
    )
  end

  def run
    if session.type == 'shell' && !session.is_a?(Msf::Sessions::SshCommandShellBind)
      print_error("Session #{datastore["SESSION"]} is a shell session.")
      print_error('Only SSH shell sessions support socket channels.')
      return
    end

    super
  end

  def tcp_client_socket_pair(params={}, timeout: datastore['TIMEOUT'])
    params = Rex::Socket::Parameters.new('Proto' => 'tcp', 'PeerHost' => datastore['LHOST'], **params)

    server = TCPSocketServer.new(host: params.peerhost, port: params.peerport)
    params.peerport = server.port
    # DEBUG(2026-07): trace channel setup timing so we can pinpoint hangs on
    # the malleable-C2 / PHP HTTP transport. Remove once stable.
    debug_ts_start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    print_status("DEBUG: session.create -> #{params.peerhost}:#{params.peerport} (tcp client channel)")
    client = session.create(params)
    print_status("DEBUG: session.create returned in #{'%.2f' % (Process.clock_gettime(Process::CLOCK_MONOTONIC) - debug_ts_start)}s cid=#{debug_channel_id(client)} client.class=#{client.class}")
    debug_ts_start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    server_client = server.start(timeout: timeout)
    print_status("DEBUG: server.start returned in #{'%.2f' % (Process.clock_gettime(Process::CLOCK_MONOTONIC) - debug_ts_start)}s")
    server.stop
    [client, server_client]
  end

  # DEBUG(2026-07): best-effort resolver for the meterpreter channel id backing
  # a socket returned by session.create — may be a Rex::Post::Meterpreter::Stream,
  # a TCPSocket-like wrapper, or a plain socket depending on the session. Never
  # raises so debug prints don't crash the test.
  def debug_channel_id(socket_or_channel)
    return socket_or_channel.cid if socket_or_channel.respond_to?(:cid)

    # Rex::Socket wrappers expose the underlying channel via #channel
    if socket_or_channel.respond_to?(:channel) && socket_or_channel.channel.respond_to?(:cid)
      return socket_or_channel.channel.cid
    end

    # Some wrappers expose the socket via #sock; peek at instance vars as a last resort
    inner = socket_or_channel.instance_variable_get(:@channel) || socket_or_channel.instance_variable_get(:@sock)
    return inner.cid if inner.respond_to?(:cid)

    '?'
  rescue StandardError
    '?'
  end

  def tcp_server_socket_trio(params={}, timeout: datastore['TIMEOUT'])
    params = Rex::Socket::Parameters.new('Proto' => 'tcp', 'LocalHost' => datastore['RHOST'], 'Server' => true, **params)

    server = session.create(params)
    client_connector = TCPSocketClient.new(host: server.params.localhost, port: server.params.localport)
    client = client_connector.start(timeout: timeout)
    server_client = server.accept
    client_connector.stop

    [client, server_client, server]
  end

  def tcp_server_socket_pair(params={}, timeout: datastore['TIMEOUT'])
    client, server_client, server = tcp_server_socket_trio(params, timeout: timeout)
    server.close
    [client, server_client]
  end

  def udp_socket_pair(params={})
    params = Rex::Socket::Parameters.new('Proto' => 'udp', 'PeerHost' => datastore['LHOST'], 'LocalHost' => datastore['RHOST'], **params)

    server = UDPSocket.new
    server.bind(params.peerhost, params.peerport)
    params.peerport = server.addr[1] if params.peerport == 0
    client = session.create(params)
    [client, server]
  end

  def test_tcp_client_channel
    print_status('Running TCP client channel tests...')

    it '[TCP-Client] Allows binding to port 0' do
      # if this fails all the other tests will fail
      # it's critical that we allow the OS to pick the port and that it's sent back to Metasploit
      client, server_client, server = tcp_client_socket_pair({'LocalPort' => 0})
      ret = client.localport != 0
      client.close
      server_client.close
      ret
    end

    it '[TCP-Client] Has the correct peer information' do
      client, server_client = tcp_client_socket_pair
      address = server_client.local_address
      ret = client.peerhost == address.ip_address && client.peerport == address.ip_port
      client.close
      server_client.close
      ret
    end

    it '[TCP-Client] Receives data from the peer' do
      client, server_client = tcp_client_socket_pair
      data = Random.new.bytes(rand(10..100))
      # DEBUG(2026-07): trace payload/timing to find where malleable-C2 PHP hangs.
      # Guard cid lookup — client may be a plain socket wrapper without #cid.
      dbg_cid = debug_channel_id(client)
      print_status("DEBUG: cid=#{dbg_cid} client.class=#{client.class} server_client.write #{data.length} bytes to peer")
      t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      server_client.write(data)
      print_status("DEBUG: server_client.write returned in #{'%.2f' % (Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0)}s; calling client.read(#{data.length})...")
      t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      received = client.read(data.length)
      print_status("DEBUG: client.read returned in #{'%.2f' % (Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0)}s; got #{received.nil? ? 'nil' : "#{received.length} bytes"}")
      ret = received == data
      client.close
      server_client.close
      ret
    end

    it '[TCP-Client] Sends data to the peer' do
      client, server_client = tcp_client_socket_pair
      data = Random.new.bytes(rand(10..100))
      # DEBUG(2026-07): trace payload/timing to find where malleable-C2 PHP hangs.
      dbg_cid = debug_channel_id(client)
      print_status("DEBUG: cid=#{dbg_cid} client.class=#{client.class} client.write #{data.length} bytes")
      t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      client.write(data)
      print_status("DEBUG: client.write returned in #{'%.2f' % (Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0)}s; server_client.read...")
      t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      received = server_client.read(data.length)
      print_status("DEBUG: server_client.read returned in #{'%.2f' % (Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0)}s; got #{received.nil? ? 'nil' : "#{received.length} bytes"}")
      ret = received == data
      client.close
      server_client.close
      ret
    end

    it '[TCP-Client] Propagates close events to the peer' do
      client, server_client = tcp_client_socket_pair
      # DEBUG(2026-07): trace close propagation direction (client -> peer).
      dbg_cid = debug_channel_id(client)
      print_status("DEBUG: cid=#{dbg_cid} client.class=#{client.class} calling client.close")
      t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      client.close
      print_status("DEBUG: client.close returned in #{'%.2f' % (Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0)}s; polling server_client.eof? ...")
      # Use IO.select with a short poll interval to avoid blocking indefinitely on eof?
      t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      ret = retry_until_truthy(timeout: datastore['TIMEOUT']) do
        IO.select([server_client], nil, nil, 0.1) && server_client.eof?
      end
      print_status("DEBUG: retry loop finished in #{'%.2f' % (Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0)}s ret=#{ret.inspect}")
      server_client.close
      ret
    end

    it '[TCP-Client] Propagates close events from the peer' do
      client, server_client = tcp_client_socket_pair
      # DEBUG(2026-07): trace close propagation direction (peer -> client). On
      # HTTP transports the framework can only learn about a peer close via an
      # explicit core_channel_read poll returning EOF/failure.
      dbg_cid = debug_channel_id(client)
      print_status("DEBUG: cid=#{dbg_cid} client.class=#{client.class} calling server_client.close")
      server_client.close
      # this behavior is wrong, it should just be an EOF, but when the channel is cleaned up, the socket is closed
      # this is how it's worked for years, so we'll test that it's still consistently wrong
      t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      dbg_last_state = nil
      ret = retry_until_truthy(timeout: datastore['TIMEOUT']) do
        state = "closed?=#{client.closed?} eof?=#{client.respond_to?(:eof?) ? client.eof? : 'n/a'} elapsed=#{'%.1f' % (Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0)}s"
        if state != dbg_last_state
          print_status("DEBUG: cid=#{dbg_cid} #{state}")
          dbg_last_state = state
        end
        client.closed?
      end
      print_status("DEBUG: retry loop finished ret=#{ret.inspect} final state closed?=#{client.closed?}")
      ret
    end
  end

  def test_tcp_server_channel
    print_status('Running TCP server channel tests...')

    it '[TCP-Server] Allows binding to port 0' do
      # if this fails all the other tests will fail
      # it's critical that we allow the OS to pick the port and that it's sent back to Metasploit
      client, server_client, server = tcp_server_socket_trio({'LocalPort' => 0})
      ret = server.params.localport != 0
      server.close
      server_client.close
      client.close
      ret
    end

    it '[TCP-Server] Accepts a connection' do
      client, server_client = tcp_server_socket_pair
      ret = !server_client.nil?
      server_client&.close
      client&.close
      ret
    end

    it '[TCP-Server] Has the correct peer information' do
      client, server_client = tcp_server_socket_pair
      address = client.local_address
      ret = server_client.peerhost == address.ip_address && server_client.peerport == address.ip_port
      server_client.close
      client.close
      ret
    end

    it '[TCP-Server] Receives data from the peer' do
      client, server_client = tcp_server_socket_pair
      data = Random.new.bytes(rand(10..100))
      client.write(data)
      ret = server_client.read(data.length) == data
      server_client.close
      client.close
      ret
    end

    it '[TCP-Server] Sends data to the peer' do
      client, server_client = tcp_server_socket_pair
      data = Random.new.bytes(rand(10..100))
      server_client.write(data)
      ret = client.read(data.length) == data
      server_client.close
      client.close
      ret
    end

    it '[TCP-Server] Propagates close events to the server' do
      client, server_client, server = tcp_server_socket_trio
      server.close

      # Try to connect a new client - should fail since server is closed
      ret = retry_until_truthy(timeout: datastore['TIMEOUT']) do
        begin
          new_client = TCPSocket.new(server.params.localhost, server.params.localport)
          new_client.close
        rescue Errno::ECONNREFUSED, Errno::ECONNRESET
          true
        else
          false
        end
      end

      server_client.close
      client.close
      ret
    end

    it '[TCP-Server] Propagates close events to the peer' do
      client, server_client = tcp_server_socket_pair
      server_client.close
      # Use IO.select with a short poll interval to avoid blocking indefinitely on eof?
      ret = retry_until_truthy(timeout: datastore['TIMEOUT']) do
        IO.select([client], nil, nil, 0.1) && client.eof?
      end
      client.close
      ret
    end

    it '[TCP-Server] Propagates close events from the peer' do
      client, server_client = tcp_server_socket_pair
      client.close
      # this behavior is wrong, it should just be an EOF, but when the channel is cleaned up, the socket is closed
      # this is how it's worked for years, so we'll test that it's still consistently wrong
      ret = retry_until_truthy(timeout: datastore['TIMEOUT']) { server_client.closed? }
      ret
    end
  end

  def test_udp_channel
    if session.is_a?(Msf::Sessions::SshCommandShellBind)
      print_warning('UDP channels are not supported by SSH sessions.')
      return
    end

    print_status('Running UDP channel tests...')

    it '[UDP] Allows binding to port 0' do
      # if this fails all the other tests will fail
      # it's critical that we allow the OS to pick the port and that it's sent back to Metasploit
      client, server_client = udp_socket_pair({'LocalPort' => 0})
      ret = client.localport != 0
      client.close
      server_client.close
      ret
    end

    it '[UDP] Has the correct peer information' do
      client, server_client = udp_socket_pair
      data = Random.new.bytes(rand(10..100))
      # Now server can send to the client's address
      server_client.send(data, 0, client.localhost, client.localport)
      ret = IO.select([client], nil, nil, datastore['TIMEOUT'])
      if ret
        _, addrinfo = client.recvfrom(data.length)
        expected_family = 'AF_INET'
        expected_port = server_client.local_address.ip_port
        expected_addr = server_client.local_address.ip_address
        ret = addrinfo.is_a?(Array)
        unless ret
          print_error("Expected addrinfo to be an Array, got #{addrinfo.class}")
        end
        ret &&= addrinfo[0] == expected_family
        unless addrinfo[0] == expected_family
          print_error("Expected address family #{expected_family.inspect}, got #{addrinfo[0].inspect}")
        end
        ret &&= addrinfo[1] == expected_port
        unless addrinfo[1] == expected_port
          print_error("Expected peer port #{expected_port}, got #{addrinfo[1].inspect}")
        end
        ret &&= addrinfo[3] == expected_addr
        unless addrinfo[3] == expected_addr
          print_error("Expected peer address #{expected_addr.inspect}, got #{addrinfo[3].inspect}")
        end
      else
        print_error("Timed out after #{datastore['TIMEOUT']}s waiting to receive data from peer")
        ret = false
      end
      client.close
      server_client.close
      ret
    end

    it '[UDP] Receives data from the peer' do
      client, server_client = udp_socket_pair
      data = Random.new.bytes(rand(10..100))
      server_client.send(data, 0, client.localhost, client.localport)
      ret = IO.select([client], nil, nil, datastore['TIMEOUT'])
      if ret
        received, _ = client.recvfrom(data.length)
        ret = received == data
      else
        print_error("Timed out after #{datastore['TIMEOUT']}s waiting to receive data from peer")
        ret = false
      end
      client.close
      server_client.close
      ret
    end

    it '[UDP] Sends data to the peer' do
      client, server_client = udp_socket_pair
      data = Random.new.bytes(rand(10..100))
      client.send(data, 0, server_client.local_address.ip_address, server_client.local_address.ip_port)
      ret = IO.select([server_client], nil, nil, datastore['TIMEOUT'])
      if ret
        received, _ = server_client.recvfrom(data.length)
        ret = received == data
      else
        print_error("Timed out after #{datastore['TIMEOUT']}s waiting to receive data from peer")
        ret = false
      end
      client.close
      server_client.close
      ret
    end
  end

  class TCPSocketServer
    attr_reader :host, :port, :client_socket

    def initialize(host:, port:)
      @host = host
      @server = TCPServer.new(host, port)
      @port = @server.addr[1]
      @client_socket = nil
      @mutex = Mutex.new
      @cv = ConditionVariable.new
      @error = nil
    end

    def start(timeout: 5)
      @thread = Thread.new do
        begin
          @client_socket = @server.accept
          @mutex.synchronize { @cv.signal }
        rescue => e
          @mutex.synchronize do
            @error = e
            @cv.signal
          end
        end
      end

      # Wait for connection with timeout
      @mutex.synchronize do
        unless @cv.wait(@mutex, timeout)
          @thread.kill
          raise "Timeout waiting for client connection after #{timeout}s"
        end

        raise @error if @error
      end

      @client_socket
    end

    def stop
      @server.close
      @thread&.join(1)
    end
  end

  class TCPSocketClient
    attr_reader :host, :port, :server_socket

    def initialize(host:, port:)
      @host = host
      @port = port
      @server_socket = nil
      @mutex = Mutex.new
      @cv = ConditionVariable.new
      @error = nil
    end

    def start(timeout: 5)
      @thread = Thread.new do
        begin
          @server_socket = TCPSocket.new(@host, @port)
          @mutex.synchronize { @cv.signal }
        rescue => e
          @mutex.synchronize do
            @error = e
            @cv.signal
          end
        end
      end

      # Wait for connection with timeout
      @mutex.synchronize do
        unless @cv.wait(@mutex, timeout)
          @thread.kill
          raise "Timeout waiting for client connection after #{timeout}s"
        end

        raise @error if @error
      end

      @server_socket
    end

    def stop
      @thread&.join(1)
    end
  end
end
