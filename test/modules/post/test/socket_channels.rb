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

  def tcp_client_socket_pair(params={}, timeout: 5)
    params = Rex::Socket::Parameters.new('Proto' => 'tcp', 'PeerHost' => datastore['LHOST'], **params)

    server = TCPSocketServer.new(host: params.peerhost, port: params.peerport)
    params.peerport = server.port
    client = session.create(params)
    server_client = server.start(timeout: timeout)
    server.stop
    [client, server_client]
  end

  def tcp_server_socket_trio(params={}, timeout: 5)
    params = Rex::Socket::Parameters.new('Proto' => 'tcp', 'LocalHost' => datastore['RHOST'], 'Server' => true, **params)

    server = session.create(params)
    client_connector = TCPSocketClient.new(host: server.params.localhost, port: server.params.localport)
    client = client_connector.start(timeout: timeout)
    server_client = server.accept
    client_connector.stop

    [client, server_client, server]
  end

  def tcp_server_socket_pair(params={}, timeout: 5)
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
      server_client.write(data)
      ret = client.read(data.length) == data
      client.close
      server_client.close
      ret
    end

    it '[TCP-Client] Sends data to the peer' do
      client, server_client = tcp_client_socket_pair
      data = Random.new.bytes(rand(10..100))
      client.write(data)
      ret = server_client.read(data.length) == data
      client.close
      server_client.close
      ret
    end

    it '[TCP-Client] Propagates close events to the peer' do
      client, server_client = tcp_client_socket_pair
      client.close
      ret = retry_until_truthy(timeout: 5) { server_client.eof? }
      server_client.close
      ret
    end

    it '[TCP-Client] Propagates close events from the peer' do
      client, server_client = tcp_client_socket_pair
      server_client.close
      # this behavior is wrong, it should just be an EOF, but when the channel is cleaned up, the socket is closed
      # this is how it's worked for years, so we'll test that it's still consistently wrong
      retry_until_truthy(timeout: 5) { client.closed? }
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
      ret = retry_until_truthy(timeout: 5) do
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
      ret = retry_until_truthy(timeout: 5) { client.eof? }
      client.close
      ret
    end

    it '[TCP-Server] Propagates close events from the peer' do
      client, server_client = tcp_server_socket_pair
      client.close
      # this behavior is wrong, it should just be an EOF, but when the channel is cleaned up, the socket is closed
      # this is how it's worked for years, so we'll test that it's still consistently wrong
      ret = retry_until_truthy(timeout: 5) { server_client.closed? }
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
      # this one is expected to fail because #recvfrom just returns a string address which is inconsistent
      client, server_client = udp_socket_pair
      data = Random.new.bytes(rand(10..100))
      # Now server can send to the client's address
      server_client.send(data, 0, client.localhost, client.localport)
      _, addrinfo = client.recvfrom(data.length)
      ret = addrinfo.is_a?(Array)
      ret &&= addrinfo[0] == 'AF_INET'
      ret &&= addrinfo[1] == server_client.local_address.ip_port
      ret &&= addrinfo[3] == server_client.local_address.ip_address
      client.close
      server_client.close
      ret
    end

    it '[UDP] Receives data from the peer' do
      client, server_client = udp_socket_pair
      data = Random.new.bytes(rand(10..100))
      server_client.send(data, 0, client.localhost, client.localport)
      received, _ = client.recvfrom(data.length)
      ret = received == data
      client.close
      server_client.close
      ret
    end

    it '[UDP] Sends data to the peer' do
      client, server_client = udp_socket_pair
      data = Random.new.bytes(rand(10..100))
      client.send(data, 0, server_client.local_address.ip_address, server_client.local_address.ip_port)
      received, _ = server_client.recvfrom(data.length)
      ret = received == data
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
