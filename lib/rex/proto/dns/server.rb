# -*- coding: binary -*-

require 'rex/socket'

module Rex
module Proto
module DNS

class Server

  class MockDnsClient
    extend Forwardable
    attr_reader :peerhost, :peerport, :srvsock

    def_delegators :@srvsock, :localhost, :localport, :sendto

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
  attr_accessor :serve_tcp, :serve_udp, :fwd_res, :cache, :start_cache
  attr_reader :serve_udp, :serve_tcp, :sock_options, :lock, :udp_sock, :tcp_sock

  #
  # Create DNS Server
  #
  # @param lhost [String] Listener address
  # @param lport [Fixnum] Listener port
  # @param udp [TrueClass, FalseClass] Listen on UDP socket
  # @param tcp [TrueClass, FalseClass] Listen on TCP socket
  # @param start_cache [TrueClass, FalseClass] Start the cache on initialization
  # @param res [Rex::Proto::DNS::Resolver] Resolver to use, nil to create a fresh one
  # @param comm [Object] Communication object for sockets
  # @param ctx [Hash] Framework context for sockets
  # @param dblock [Proc] Handler for :dispatch_request flow control interception
  # @param sblock [Proc] Handler for :send_response flow control interception
  #
  # @return [Rex::Proto::DNS::Server] DNS Server object
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
    # Dnsruby#dup is shallow - req and forward share the same @question Array.
    # Give forward its own copy so deleting forwarded questions doesn't also
    # empty req.question, which we need intact when echoing it in the response.
    forward.instance_variable_set(:@question, req.question.dup)
    answers = []
    # Find cached items, remove question from forwarded packet
    req.question.each do |ques|
      cached = self.cache.find(ques.qname, ques.qtype)
      unless cached.empty?
        answers.concat(cached)
        forward.question.delete(ques)
      end
    end
    # Forward remaining requests, cache responses
    if forward.question.count > 0 && @fwd_res
      forwarded = self.fwd_res.send(forward)
      answers.concat(forwarded.answer)
      forwarded.answer.each { |ans| self.cache.cache_record(ans) }
    end
    # Build a fresh response message to avoid a Dnsruby stale-state encoding bug
    # where instance_variable_set(:@answer) on a decoded request appends answer
    # bytes after the packet end rather than inside the answer section.
    resp = Dnsruby::Message.new
    resp.header.id = req.header.id
    resp.header.qr = true
    resp.header.ra = req.header.rd
    req.question.each { |q| resp.add_question(q.qname, q.qtype, q.qclass) }
    answers.uniq.each { |a| resp.add_answer(a) }
    send_response(cli, resp.encode)
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
        buf, addr, source_port = self.udp_sock.recvfrom(65535)
        if source_port
          host, port = addr, source_port
        else
          host, port = addr[3], addr[1]
        end
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
