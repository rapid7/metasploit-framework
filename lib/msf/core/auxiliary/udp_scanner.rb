# -*- coding: binary -*-

module Msf

###
#
# This module provides methods for scanning UDP services
#
###
module Auxiliary::UDPScanner
  include Auxiliary::Scanner

  # A hash of results of a given batch run, keyed by host
  attr_accessor :results

  #
  # Initializes an instance of an auxiliary module that scans UDP
  #
  def initialize(info = {})
    super

    register_options(
    [
      Opt::RPORT,
      OptInt.new('BATCHSIZE', [true, 'The number of hosts to probe in each set', 256]),
      OptInt.new('THREADS', [true, "The number of concurrent threads", 10])
    ], self.class)

    register_advanced_options(
    [
      Opt::CHOST,
      Opt::CPORT,
      OptInt.new('ScannerRecvInterval', [true, 'The maximum numbers of sends before entering the processing loop', 30]),
      OptInt.new('ScannerMaxResends', [true, 'The maximum times to resend a packet when out of buffers', 10]),
      OptInt.new('ScannerRecvQueueLimit', [true, 'The maximum queue size before breaking out of the processing loop', 100]),
      OptInt.new('ScannerRecvWindow', [true, 'The number of seconds to wait post-scan to catch leftover replies', 15])

    ], self.class)
  end

  # Define our batch size
  def run_batch_size
    datastore['BATCHSIZE'].to_i
  end

  def udp_socket(ip, port, bind_peer: true)
    key = "#{ip}:#{port}:#{bind_peer ? 'bound' : 'unbound'}"
    @udp_sockets_mutex.synchronize do
      unless @udp_sockets.key?(key)
        sock_info = {
          'LocalHost' => datastore['CHOST'] || nil,
          'LocalPort' => datastore['CPORT'] || 0,
          'Context'   => { 'Msf' => framework, 'MsfExploit' => self }
        }
        if bind_peer
          sock_info['PeerHost'] = ip
          sock_info['PeerPort'] = port
        end
        @udp_sockets[key] = Rex::Socket::Udp.create(sock_info)
        add_socket(@udp_sockets[key])
      end
      return @udp_sockets[key]
    end
  end

  def cleanup_udp_sockets
    @udp_sockets_mutex.synchronize do
      @udp_sockets.each do |key, sock|
        @udp_sockets.delete(key)
        remove_socket(sock)
        sock.close
      end
    end
  end

  # Start scanning a batch of IP addresses
  def run_batch(batch)
    @udp_sockets = {}
    @udp_sockets_mutex = Mutex.new

    @udp_send_count = 0
    @interval_mutex = Mutex.new

    # Provide a hook for pre-scanning setup
    scanner_prescan(batch)

    # Call the including module once per IP
    batch.each do |ip|
      scan_host(ip)
    end

    # Catch any stragglers
    stime = Time.now.to_f

    while Time.now.to_f < ( stime + datastore['ScannerRecvWindow'] )
      scanner_recv(1.0)
    end

    # Provide a hook for post-scanning processing
    scanner_postscan(batch)
  end

  # Send a spoofed packet to a given host and port
  def scanner_spoof_send(data, ip, port, srcip, num_packets=1)
    open_pcap
    p = PacketFu::UDPPacket.new
    p.ip_saddr = srcip
    p.ip_daddr = ip
    p.ip_ttl = 255
    p.udp_src = (rand((2**16)-1024)+1024).to_i
    p.udp_dst = port
    p.payload = data
    p.recalc
    print_status("Sending #{num_packets} packet(s) to #{ip} from #{srcip}")
    1.upto(num_packets) do |x|
      break unless capture_sendto(p, ip)
    end
    close_pcap
  end

  # Send a packet to a given host and port
  def scanner_send(data, ip, port)

    # flatten any bindata objects
    data = data.to_binary_s if data.respond_to?('to_binary_s')

    resend_count = 0

    begin
      addrinfo = Addrinfo.ip(ip)
      unless addrinfo.ipv4_multicast? || addrinfo.ipv6_multicast?
        sock = udp_socket(ip, port, bind_peer: true)
        sock.send(data, 0)
      else
        sock = udp_socket(ip, port, bind_peer: false)
        sock.sendto(data, ip, port, 0)
      end

    rescue ::Errno::ENOBUFS
      resend_count += 1
      if resend_count > datastore['ScannerMaxResends']
        vprint_error("#{ip}:#{port} Max resend count hit sending #{data.length}")
        return false
      end

      scanner_recv(0.1)
      sleep(0.25)

      retry

    rescue ::Rex::ConnectionError, ::Errno::ECONNREFUSED
      # This fires for host unreachable, net unreachable, and broadcast sends
      # We can safely ignore all of these for UDP sends
    end

    @interval_mutex.synchronize do
      @udp_send_count += 1
      if @udp_send_count % datastore['ScannerRecvInterval'] == 0
        scanner_recv(0.1)
      end
    end

    true
  end

  # Process incoming packets and dispatch to the module
  # Ensure a response flood doesn't trap us in a loop
  # Ignore packets outside of our project's scope
  def scanner_recv(timeout = 0.1)
    queue = []
    start = Time.now
    while Time.now - start < timeout do
      readable, _, _ = ::IO.select(@udp_sockets.values, nil, nil, timeout)
      if readable
        for sock in readable
          res = sock.recvfrom(65535, timeout)

          # Ignore invalid responses
          break if not res[1]

          # Ignore empty responses
          next if not (res[0] and res[0].length > 0)

          # Trim the IPv6-compat prefix off if needed
          shost = res[1].sub(/^::ffff:/, '')

          # Ignore the response if we have a boundary
          next unless inside_workspace_boundary?(shost)

          queue << [res[0], shost, res[2]]

          if queue.length > datastore['ScannerRecvQueueLimit']
            break
          end
        end
      end
    end

    cleanup_udp_sockets

    queue.each do |q|
      scanner_process(*q)
    end

    queue.length
  end

  def cport
    datastore['CPORT']
  end

  def rport
    datastore['RPORT']
  end

  #
  # The including module may override some of these methods
  #

  # Builds and returns the probe to be sent
  def build_probe
  end

  # Called for each IP in the batch.  This will send all necessary probes.
  def scan_host(ip)
    scanner_send(build_probe, ip, rport)
  end

  # Called for each response packet
  def scanner_process(data, shost, _sport)
    @results[shost] ||= []
    @results[shost] << data
  end

  # Called before the scan block
  def scanner_prescan(batch)
    vprint_status("Sending probes to #{batch[0]}->#{batch[-1]} (#{batch.length} hosts)")
    @results = {}
  end

  # Called after the scan block
  def scanner_postscan(batch)
  end
end
end
