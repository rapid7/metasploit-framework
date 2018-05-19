# -*- coding: binary -*-

require 'rex/socket'
require 'rex/proto/dhcp'

module Rex
module Proto
module DHCP

##
#
# DHCP Server class
# not completely configurable - written specifically for a PXE server
# - scriptjunkie
#
# extended to support testing/exploiting CVE-2011-0997
# - apconole@yahoo.com
##

class Server

  include Rex::Socket

  def initialize(hash, context = {})
    self.listen_host = '0.0.0.0' # clients don't already have addresses. Needs to be 0.0.0.0
    self.listen_port = 67 # mandatory (bootps)
    self.context = context
    self.sock = nil

    self.myfilename = hash['FILENAME'] || ""
    self.myfilename << ("\x00" * (128 - self.myfilename.length))

    source = hash['SRVHOST'] || Rex::Socket.source_address
    self.ipstring = Rex::Socket.addr_aton(source)

    ipstart = hash['DHCPIPSTART']
    if ipstart
      self.start_ip = Rex::Socket.addr_atoi(ipstart)
    else
      # Use the first 3 octects of the server's IP to construct the
      # default range of x.x.x.32-254
      self.start_ip = "#{self.ipstring[0..2]}\x20".unpack("N").first
    end
    self.current_ip = start_ip

    ipend = hash['DHCPIPEND']
    if ipend
      self.end_ip = Rex::Socket.addr_atoi(ipend)
    else
      # Use the first 3 octects of the server's IP to construct the
      # default range of x.x.x.32-254
      self.end_ip = "#{self.ipstring[0..2]}\xfe".unpack("N").first
    end

    # netmask
    netmask = hash['NETMASK'] || "255.255.255.0"
    self.netmaskn = Rex::Socket.addr_aton(netmask)

    # router
    router = hash['ROUTER'] || source
    self.router = Rex::Socket.addr_aton(router)

    # dns
    dnsserv = hash['DNSSERVER'] || source
    self.dnsserv = Rex::Socket.addr_aton(dnsserv)

    # broadcast
    if hash['BROADCAST']
      self.broadcasta = Rex::Socket.addr_aton(hash['BROADCAST'])
    else
      self.broadcasta = Rex::Socket.addr_itoa( self.start_ip | (Rex::Socket.addr_ntoi(self.netmaskn) ^ 0xffffffff) )
    end

    self.served = {}
    self.serveOnce = hash.include?('SERVEONCE')

    self.servePXE = (hash.include?('PXE') or hash.include?('FILENAME') or hash.include?('PXEONLY'))
    self.serveOnlyPXE = hash.include?('PXEONLY')

    # Always assume we don't give out hostnames ...
    self.give_hostname = false
    self.served_over = 0
    if (hash['HOSTNAME'])
      self.give_hostname = true
      self.served_hostname = hash['HOSTNAME']
      if ( hash['HOSTSTART'] )
        self.served_over = hash['HOSTSTART'].to_i
      end
    end

    self.leasetime = 600
    self.relayip = "\x00\x00\x00\x00" # relay ip - not currently suported
    self.pxeconfigfile = "update2"
    self.pxealtconfigfile = "update0"
    self.pxepathprefix = ""
    self.pxereboottime = 2000

    self.domain_name = hash['DOMAINNAME'] || nil
    self.url = hash['URL'] if hash.include?('URL')
  end

  def report(&block)
    self.reporter = block
  end

  # Start the DHCP server
  def start
    self.sock = Rex::Socket::Udp.create(
      'LocalHost' => listen_host,
      'LocalPort' => listen_port,
      'Context'   => context
    )

    self.thread = Rex::ThreadFactory.spawn("DHCPServerMonitor", false) {
      monitor_socket
    }
  end

  # Stop the DHCP server
  def stop
    self.thread.kill
    self.served = {}
    self.sock.close rescue nil
  end


  # Set an option
  def set_option(opts)
    allowed_options = [
      :serveOnce, :pxealtconfigfile, :servePXE, :relayip, :leasetime, :dnsserv,
      :pxeconfigfile, :pxepathprefix, :pxereboottime, :router, :proxy_auto_discovery,
      :give_hostname, :served_hostname, :served_over, :serveOnlyPXE, :domain_name, :url
    ]

    opts.each_pair { |k,v|
      next if not v
      if allowed_options.include?(k)
        self.instance_variable_set("@#{k}", v)
      end
    }
  end


  # Send a single packet to the specified host
  def send_packet(ip, pkt)
    port = 68 # bootpc
    if ip
      self.sock.sendto( pkt, ip, port )
    else
      if not self.sock.sendto( pkt, '255.255.255.255', port )
        self.sock.sendto( pkt, self.broadcasta, port )
      end
    end
  end

  attr_accessor :listen_host, :listen_port, :context, :leasetime, :relayip, :router, :dnsserv
  attr_accessor :domain_name, :proxy_auto_discovery
  attr_accessor :sock, :thread, :myfilename, :ipstring, :served, :serveOnce
  attr_accessor :current_ip, :start_ip, :end_ip, :broadcasta, :netmaskn
  attr_accessor :servePXE, :pxeconfigfile, :pxealtconfigfile, :pxepathprefix, :pxereboottime, :serveOnlyPXE
  attr_accessor :give_hostname, :served_hostname, :served_over, :reporter, :url

protected


  # See if there is anything to do.. If so, dispatch it.
  def monitor_socket
    while true
      rds = [@sock]
      wds = []
      eds = [@sock]

      r,_,_ = ::IO.select(rds,wds,eds,1)

      if (r != nil and r[0] == self.sock)
        buf,host,port = self.sock.recvfrom(65535)
        # Lame compatabilitiy :-/
        from = [host, port]
        dispatch_request(from, buf)
      end

    end
  end

  def dhcpoption(type, val = nil)
    ret = ''
    ret << [type].pack('C')

    if val
      ret << [val.length].pack('C') + val
    end

    ret
  end

  # Dispatch a packet that we received
  def dispatch_request(from, buf)
    type = buf.unpack('C').first
    if (type != Request)
      #dlog("Unknown DHCP request type: #{type}")
      return
    end

    # parse out the members
    _hwtype = buf[1,1]
    hwlen = buf[2,1].unpack("C").first
    _hops = buf[3,1]
    _txid = buf[4..7]
    _elapsed = buf[8..9]
    _flags = buf[10..11]
    clientip = buf[12..15]
    _givenip = buf[16..19]
    _nextip = buf[20..23]
    _relayip = buf[24..27]
    _clienthwaddr = buf[28..(27+hwlen)]
    servhostname = buf[44..107]
    _filename = buf[108..235]
    magic = buf[236..239]

    if (magic != DHCPMagic)
      #dlog("Invalid DHCP request - bad magic.")
      return
    end

    messageType = 0
    pxeclient = false

    # options parsing loop
    spot = 240
    while (spot < buf.length - 3)
      optionType = buf[spot,1].unpack("C").first
      break if optionType == 0xff

      optionLen = buf[spot + 1,1].unpack("C").first
      optionValue = buf[(spot + 2)..(spot + optionLen + 1)]
      spot = spot + optionLen + 2
      if optionType == 53
        messageType = optionValue.unpack("C").first
      elsif optionType == 150 or (optionType == 60 and optionValue.include? "PXEClient")
        pxeclient = true
      end
    end

    # don't serve if only serving PXE and not PXE request
    return if pxeclient == false and self.serveOnlyPXE == true

    # prepare response
    pkt = [Response].pack('C')
    pkt << buf[1..7] #hwtype, hwlen, hops, txid
    pkt << "\x00\x00\x00\x00"  #elapsed, flags
    pkt << clientip

    # if this is somebody we've seen before, use the saved IP
    if self.served.include?( buf[28..43] )
      pkt << Rex::Socket.addr_iton(self.served[buf[28..43]][0])
    else # otherwise go to next ip address
      self.current_ip += 1
      if self.current_ip > self.end_ip
        self.current_ip = self.start_ip
      end
      self.served.merge!( buf[28..43] => [ self.current_ip, messageType == DHCPRequest ] )
      pkt << Rex::Socket.addr_iton(self.current_ip)
    end
    pkt << self.ipstring #next server ip
    pkt << self.relayip
    pkt << buf[28..43] #client hw address
    pkt << servhostname
    pkt << self.myfilename
    pkt << magic
    pkt << "\x35\x01" #Option

    if messageType == DHCPDiscover  #DHCP Discover - send DHCP Offer
      pkt << [DHCPOffer].pack('C')
      # check if already served an Ack based on hw addr (MAC address)
      # if serveOnce & PXE, don't reply to another PXE request
      # if serveOnce & ! PXE, don't reply to anything
      if self.serveOnce == true and self.served.has_key?(buf[28..43]) and
          self.served[buf[28..43]][1] and (pxeclient == false or self.servePXE == false)
        return
      end
    elsif messageType == DHCPRequest #DHCP Request - send DHCP ACK
      pkt << [DHCPAck].pack('C')
      # now we ignore their discovers (but we'll respond to requests in case a packet was lost)
      if ( self.served_over != 0 )
        # NOTE: this is sufficient for low-traffic net
        # for high-traffic, this will probably lead to
        # hostname collision
        self.served_over += 1
      end
    else
      return  # ignore unknown DHCP request
    end

    # Options!
    pkt << dhcpoption(OpProxyAutodiscovery, self.proxy_auto_discovery) if self.proxy_auto_discovery
    pkt << dhcpoption(OpDHCPServer, self.ipstring)
    pkt << dhcpoption(OpLeaseTime, [self.leasetime].pack('N'))
    pkt << dhcpoption(OpSubnetMask, self.netmaskn)
    pkt << dhcpoption(OpRouter, self.router)
    pkt << dhcpoption(OpDns, self.dnsserv)
    pkt << dhcpoption(OpDomainName, self.domain_name) if self.domain_name

    if self.servePXE  # PXE options
      pkt << dhcpoption(OpPXEMagic, PXEMagic)
      # We already got this one, serve localboot file
      if self.serveOnce == true and self.served.has_key?(buf[28..43]) and
          self.served[buf[28..43]][1] and pxeclient == true
        pkt << dhcpoption(OpPXEConfigFile, self.pxealtconfigfile)
      else
        # We are handing out an IP and our PXE attack
        if(self.reporter)
          self.reporter.call(buf[28..43],self.ipstring)
        end
        pkt << dhcpoption(OpPXEConfigFile, self.pxeconfigfile)
      end
      pkt << dhcpoption(OpPXEPathPrefix, self.pxepathprefix)
      pkt << dhcpoption(OpPXERebootTime, [self.pxereboottime].pack('N'))
      if ( self.give_hostname == true )
        send_hostname = self.served_hostname
        if ( self.served_over != 0 )
          # NOTE : see above comments for the 'uniqueness' of this value
          send_hostname += self.served_over.to_s
        end
        pkt << dhcpoption(OpHostname, send_hostname)
      end
    end
    pkt << dhcpoption(OpURL, self.url) if self.url
    pkt << dhcpoption(OpEnd)

    pkt << ("\x00" * 32) #padding

    # And now we mark as requested
    self.served[buf[28..43]][1] = true if messageType == DHCPRequest

    send_packet(nil, pkt)
  end

end

end
end
end
