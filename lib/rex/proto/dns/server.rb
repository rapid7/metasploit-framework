# -*- coding: binary -*-

require 'rex/socket'
require 'rex/proto/dns'

module Rex
module Proto
module DNS

class Server

  class Cache
    attr_reader :records
    include Rex::Proto::DNS::Constants
    # class DNSRecordError < ::Exception
    #
    # Create DNS Server cache
    #
    def initialize
      @records = {}
      @lock = Mutex.new
    end

    #
    # Find entries in cache
    #
    # @param search [String] Name or address to search for
    # @param type [String] Record type to search for
    #
    # @return [Array] Records found
    def find(search, type = 'A')
      @records.select do |record,expire|
        record.type == type and (expire < 1 or expire > Time.now.to_i) and 
        (record.name == search or record.address == search)
      end.keys
    end

    #
    # Add record to cache, only when "running"
    #
    # @param record [Net::DNS::RR] Record to cache
    def cache_record(record)
      if record.class.ancestors.include?(Net::DNS::RR) and @monitor_thread and
      Rex::Socket.is_ip_addr?(record.address.to_s) and record.name.to_s.match(MATCH_HOSTNAME)
        add(record, Time.now.to_i + record.ttl)
      else
        raise "Invalid record for cache entry - #{record.inspect}"
      end
    end

    #
    # Add static record to cache
    #
    # @param name [String] Name of record
    # @param address [String] Address of record
    # @param type [String] Record type to add
    def add_static(name, address, type = 'A')
      if Rex::Socket.is_ip_addr?(address.to_s) and name.to_s.match(MATCH_HOSTNAME)
        find(name, type).each do |found|
          delete(found)
        end
        add(Net::DNS::RR.new(:name => name, :address => address),0)
      else
        raise "Invalid parameters for static entry - #{name}, #{address}, #{type}"
      end
    end

    #
    # Prune cache entries
    #
    # @param before [Fixnum] Time in seconds before which records are evicted
    def prune(before = Time.now.to_i)
      @records.select do |rec, expire|
        expire > 0 and expire < before
      end.each {|rec, exp| delete(rec)}
    end

    #
    # Start the cache monitor
    #
    def start
      @monitor_thread = Rex::ThreadFactory.spawn("DNSServerCacheMonitor", false) {
        while true
          prune
          Rex::ThreadSafe.sleep(0.5)
        end
      } unless @monitor_thread
    end

    #
    # Stop the cache monitor
    #
    # @param flush [TrueClass,FalseClass] Remove non-static entries
    def stop(flush = false)
      @monitor_thread.kill
      @monitor_thread = nil
      if flush
        @records.select do |rec, expire|
          rec.ttl > 0
        end.each {|rec| delete(rec)}
      end
    end

    protected

    #
    # Add a record to the cache with thread safety
    #
    # @param record [Net::DNS::RR] Record to add
    # @param expire [Fixnum] Time in seconds when record becomes stale
    def add(record, expire = 0)
      @lock.synchronize do
        @records[record] = expire
      end
    end

    #
    # Delete a record from the cache with thread safety
    #
    # @param record [Net::DNS::RR] Record to delete
    def delete(record)
      @lock.synchronize do
        @records.delete(record)
      end
    end
  end # Cache

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
  attr_accessor :fwd_res, :dispatch_block, :send_block, :cache
  def initialize(lhost = '0.0.0.0', lport = 53, udp = true, tcp = false, res = nil, comm = nil, ctx = {}, dblock = nil, sblock = nil)
    
    @udp_sock = udp ? Rex::Socket::Udp.create(
      'LocalHost' => lhost,
      'LocalPort' => lport,
      'Context'   => ctx,
      'Comm'      => comm
    ) : nil
    @tcp_sock = tcp ? Rex::Socket::TcpServer.create(
      'LocalHost' => lhost,
      'LocalPort' => lport,
      'Context'   => ctx,
      'Comm'      => comm
    ) : nil
    @fwd_res = res.nil? ? Rex::Proto::DNS::Resolver.new : res
    @udp_mon = nil
    @dispatch_block = dblock
    @send_block = sblock
    @cache = Cache.new
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
    @lock.synchronize do
      @fwd_res.nameserver = ns
    end
  end

  #
  # Check if server is running
  #
  def running?
    @running == true
  end

  #
  # Start the DNS server and cache
  #
  def start
    @udp_mon = Rex::ThreadFactory.spawn("DNSServerMonitor", false) {
      monitor_udp_socket
    } if @udp_sock

    if @tcp_sock

      @tcp_sock.on_client_data_proc = Proc.new { |cli|
        on_client_data(cli)
      }
      @tcp_sock.start
    end
    @cache.start
    @running = true
  end

  #
  # Stop the DNS server and cache
  #
  # @param flush_cache [TrueClass,FalseClass] Flush DNS cache on stop
  def stop(flush_cache = false)
    if @udp_mon
      @udp_mon.kill
      @udp_mon = nil
    end
    @tcp_sock.stop if @tcp_sock
    @cache.stop(flush_cache)
    @running = false
  end

  #
  # Reconstructs a packet with both standard DNS libraries
  # Ensures that headers match the payload
  #
  # @param packet [String, Net::DNS::Packet] Data to be validated
  #
  # @return [Net::DNS::Packet]
  def validate_packet(packet)
    Net::DNS::Packet.parse(
      Resolv::DNS::Message.decode(
        packet.respond_to?(:data) ? packet.data : packet
      ).encode
    )
  end

  #
  # Process client request, handled with @dispatch_block if set
  #
  # @param cli [Rex::Socket::Tcp, Rex::Socket::Udp] Client sending the request
  # @param data [String] raw DNS request data
  def dispatch_request(cli, data)
    if @dispatch_block
      @dispatch_block.call(cli,data)
    else
      default_dispatch_request(cli,data)
    end
  end

  def default_dispatch_request(cli,data)
    req = Net::DNS::Packet.parse(data)
    forward = req.dup
    # Find cached items, remove request from forwarded packet
    req.question.each do |ques|
      cached = @cache.find(ques.qName, ques.qType.to_s)
      if cached.empty?
        next
      else
        req.answer = req.answer + cached
        forward.question.delete(ques)
      end
    end
    # Forward remaining requests, cache responses
    if forward.question.count > 0 and @fwd_res
      forwarded = @fwd_res.send(validate_packet(forward))
      req.answer = req.answer + forwarded.answer 
      forwarded.answer.each do |ans|
        @cache.cache_record(ans)
      end
      req.header.ra = 1 # Set recursion bit
    end
    # Finalize answers in response
    # Check for empty response prior to sending
    if req.answer.size < 1
      req.header.rCode = Net::DNS::Header::RCode.new(3)
    end
    req.header.qr = 1 # Set response bit
    send_response(cli, validate_packet(req).data)
  end

  #
  # Send response to client, handled with @send_block if set
  #
  # @param cli [Rex::Socket::Tcp, Rex::Socket::Udp] Client receiving the response
  # @param data [String] raw DNS response data
  def send_response(cli, data)
    if @send_block
      @send_block.call(cli, data)
    else
      cli.write(data)
    end
  end

protected

  #
  # Monitor UDP socket for incoming requests, create client object from socket
  #
  def monitor_udp_socket
    while true
      rds = [@udp_sock]
      wds = []
      eds = [@udp_sock]

      r,_,_ = ::IO.select(rds,wds,eds,1)

      if (r != nil and r[0] == @udp_sock)
        buf,host,port = @udp_sock.recvfrom(65535)
        # Mock up a client object as a Rex Socket for sending back data
        cli = Rex::Socket::Udp.create(
          'PeerHost' => host,
          'PeerPort' => port,
          'LocalHost' => @udp_sock.localhost,
          'LocalPort' => @udp_sock.localport
        )
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
      from = [cli.peerhost, cli.peerport]
      dispatch_request(cli, data)
    rescue EOFError => e
      close_client(cli)
      raise e
    end
  end

end

end
end
end
