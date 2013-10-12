# -*- coding: binary -*-

module Msf

###
#
# This module provides methods for scanning UDP services
#
###
module Auxiliary::UDPScanner

  include Auxiliary::Scanner

  #
  # Initializes an instance of an auxiliary module that scans UDP
  #

  def initialize(info = {})
    super

    register_options(
    [
      Opt::CHOST,
      OptInt.new('BATCHSIZE', [true, 'The number of hosts to probe in each set', 256]),
    ], self.class)

    register_advanced_options(
    [
      OptInt.new('ScannerRecvInterval', [true, 'The maximum numbers of sends before entering the processing loop', 30]),
      OptInt.new('ScannerMaxResends', [true, 'The maximum times to resend a packet when out of buffers', 10]),
      OptInt.new('ScannerRecvQueueLimit', [true, 'The maximum queue size before breaking out of the processing loop', 100]),
      OptInt.new('ScannerRecvWindow', [true, 'The number of seconds to wait post-scan to catch leftover replies', 15]),

    ], self.class)
  end


  # Define our batch size
  def run_batch_size
    datastore['BATCHSIZE'].to_i
  end

  # Start scanning a batch of IP addresses
  def run_batch(batch)
    @udp_sock = Rex::Socket::Udp.create({
      'LocalHost' => datastore['CHOST'] || nil,
      'Context'   => { 'Msf' => framework, 'MsfExploit' => self }
    })
    add_socket(@udp_sock)

    @udp_send_count = 0

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

  # Send a packet to a given host and port
  def scanner_send(data, ip, port)

    resend_count = 0
    begin

      @udp_sock.sendto(data, ip, port, 0)

    rescue ::Errno::ENOBUFS
      resend_count += 1
      if resend_count > datastore['ScannerMaxResends']
        vprint_error("#{ip}:#{port} Max resend count hit sending #{data.length}")
        return false
      end

      scanner_recv(0.1)

      Rex.sleep(0.25)

      retry

    rescue ::Rex::ConnectionError
      # This fires for host unreachable, net unreachable, and broadcast sends
      # We can safely ignore all of these for UDP sends
    end

    @udp_send_count += 1

    if @udp_send_count % datastore['ScannerRecvInterval'] == 0
      scanner_recv(0.1)
    end

    true
  end

  # Process incoming packets and dispatch to the module
  # Ensure a response flood doesn't trap us in a loop
  # Ignore packets outside of our project's scope
  def scanner_recv(timeout=0.1)
    queue = []
    while (res = @udp_sock.recvfrom(65535, timeout))

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

    queue.each do |q|
      scanner_process(*q)
    end

    queue.length
  end

  #
  # The including module override these methods
  #

  # Called for each IP in the batch
  def scan_host(ip)
  end

  # Called for each response packet
  def scanner_process(data, shost, sport)
  end

  # Called before the scan block
  def scanner_prescan(batch)
  end

  # Called after the scan block
  def scanner_postscan(batch)
  end

end
end
