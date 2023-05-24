# -*- coding: binary -*-

require 'rex/socket'

module Rex
module Proto
module DNS

class Server

  class MockDnsClient
    attr_reader :peerhost, :peerport, :srvsock

    #
    # Create mock DNS client
    #
    # @param host [String] PeerHost IP address
    # @param port [Fixnum] PeerPort integer
    def initialize(host, port, sock)
      @peerhost = host
      @peerport = port
      @srvsock = sock
    end

    #
    # Test method to prevent GC/ObjectSpace abuse via class lookups
    #
    def mock_dns_client?
      true
    end

    def write(data)
      srvsock.sendto(data, peerhost, peerport)
    end
  end

  include Rex::IO::GramServer

  Packet = Rex::Proto::DNS::Packet
  #
  # Create DNS Server
  #
  # @param lhost [String] Listener address
  # @param lport [Fixnum] Listener port
  # @param udp [TrueClass, FalseClass] Listen on UDP socket
  # @param tcp [TrueClass, FalseClass] Listen on TCP socket
  # @param res [Rex::Proto::DNS::Resolver] Resolver to use, nil to create a fresh one
  # @param ctx [Hash] Framework context for sockets
  # @param dblock [Proc] Handler for :dispatch_request flow control interception
  # @param sblock [Proc] Handler for :send_response flow control interception
  #
  # @return [Rex::Proto::DNS::Server] DNS Server object
  attr_accessor :serve_tcp, :serve_udp, :fwd_res, :cache, :start_cache
  attr_reader :serve_udp, :serve_tcp, :sock_options, :lock, :udp_sock, :tcp_sock
  def initialize(lhost = '0.0.0.0', lport = 53, udp = true, tcp = false, start_cache = true, res = nil, comm = nil, ctx = {}, dblock = nil, sblock = nil)

    @serve_udp = udp
    @serve_tcp = tcp
    @sock_options = {
      'LocalHost' => lhost,
      'LocalPort' => lport,
      'Context'   => ctx,
      'Comm'      => comm
    }
    self.fwd_res = res.nil? ? Rex::Proto::DNS::Resolver.new(:comm => comm, :context => ctx) : res
    self.listener_thread = nil
    self.dispatch_request_proc = dblock
    self.send_response_proc = sblock
    self.start_cache = start_cache
    self.cache = Rex::Proto::DNS::Cache.new
    @lock = Mutex.new
  end

  #
  # Switch DNS forwarders in resolver with thread safety
  #
  # @param ns [Array, String] List of (or single) nameservers to use
  def switchns(ns = [])
    if ns.respond_to?(:split)
      ns = [ns]
    end
    self.lock.synchronize do
      self.fwd_res.nameserver = ns
    end
  end

  #
  # Check if server is running
  #
  def running?
    self.listener_thread and self.listener_thread.alive?
  end

  #
  # Start the DNS server and cache
  # @param start_cache [TrueClass, FalseClass] stop the cache
  def start

    if self.serve_udp
      @udp_sock = Rex::Socket::Udp.create(self.sock_options)
      self.listener_thread = Rex::ThreadFactory.spawn("UDPDNSServerListener", false) {
        monitor_listener
      }
    end

    if self.serve_tcp
      @tcp_sock = Rex::Socket::TcpServer.create(self.sock_options)
      self.tcp_sock.on_client_data_proc = Proc.new { |cli|
        on_client_data(cli)
      }
      self.tcp_sock.start
      if !self.serve_udp
        self.listener_thread = tcp_sock.listener_thread
      end
    end

    self.cache.start if self.start_cache
  end

  #
  # Stop the DNS server and cache
  #
  # @param flush_cache [TrueClass,FalseClass] Flush eDNS cache on stop
  def stop(flush_cache = false)
    ensure_close = [self.udp_sock, self.tcp_sock].compact
    begin
      self.listener_thread.kill if self.listener_thread.respond_to?(:kill)
      self.listener_thread = nil
    ensure
      while csock = ensure_close.shift
        csock.stop if csock.respond_to?(:stop)
        csock.close unless csock.respond_to?(:close) and csock.closed?
      end
    end
    self.cache.stop(flush_cache)
  end

  #
  # Process client request, handled with dispatch_request_proc if set
  #
  # @param cli [Rex::Socket::Tcp, Rex::Socket::Udp] Client sending the request
  # @param data [String] raw DNS request data
  def dispatch_request(cli, data)
    if self.dispatch_request_proc
      self.dispatch_request_proc.call(cli,data)
    else
      default_dispatch_request(cli,data)
    end
  end

  #
  # Default DNS request dispatcher, attempts to find
  # response records in cache or forwards request upstream
  #
  # @param cli [Rex::Socket::Tcp, Rex::Socket::Udp] Client sending the request
  # @param data [String] raw DNS request data
  def default_dispatch_request(cli,data)
    return if data.strip.empty?
    req = Packet.encode_drb(data)
    forward = req.dup
    # Find cached items, remove request from forwarded packet
    req.question.each do |ques|
      cached = self.cache.find(ques.qname, ques.qtype)
      if cached.empty?
        next
      else
        req.instance_variable_set(:@answer, (req.answer + cached).uniq)
        forward.question.delete(ques)
      end
    end
    # Forward remaining requests, cache responses
    if forward.question.count > 0 and @fwd_res
      forwarded = self.fwd_res.send(forward)
      req.instance_variable_set(:@answer, (req.answer + forwarded.answer).uniq)
      forwarded.answer.each do |ans|
        self.cache.cache_record(ans)
      end
      req.header.ra = true # Set recursion bit
    end
    # Finalize answers in response
    # Check for empty response prior to sending
    if req.answer.size < 1
      req.header.rCode = Dnsruby::RCode::NOERROR
    end
    req.header.qr = true # Set response bit
    send_response(cli, req.data)
  end

  #
  # Returns the hardcore alias for the DNS service
  #
  def self.hardcore_alias(*args)
    "#{(args[0] || '')}-#{(args[1] || '')}-#{args[5] || ''}"
  end

  #
  # DNS server.
  #
  def alias
    "DNS Server"
  end


protected
  #
  # This method monitors the listener socket for new connections and calls
  # the +on_client_connect+ callback routine.
  #
  def monitor_listener
    while true
      rds = [self.udp_sock]
      wds = []
      eds = [self.udp_sock]

      r,_,_ = ::IO.select(rds,wds,eds,1)

      if (r != nil and r[0] == self.udp_sock)
        buf,host,port = self.udp_sock.recvfrom(65535)
        # Mock up a client object for sending back data
        cli = MockDnsClient.new(host, port, r[0])
        dispatch_request(cli, buf)
      end
    end
  end

  #
  # Processes request coming from client
  #
  # @param cli [Rex::Socket::Tcp] Client sending request
  def on_client_data(cli)
    begin
      data = cli.read(65535)

      raise ::EOFError if not data
      raise ::EOFError if data.empty?
      dispatch_request(cli, data)
    rescue EOFError => e
      self.tcp_socket.close_client(cli) if cli
      raise e
    end
  end

end

end
end
end
