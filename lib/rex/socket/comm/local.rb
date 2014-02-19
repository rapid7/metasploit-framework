# -*- coding: binary -*-
require 'singleton'
require 'rex/socket'
require 'rex/socket/tcp'
require 'rex/socket/ssl_tcp'
require 'rex/socket/ssl_tcp_server'
require 'rex/socket/udp'
require 'rex/socket/ip'
require 'timeout'

###
#
# Local communication class factory.
#
###
class Rex::Socket::Comm::Local

  include Singleton
  include Rex::Socket::Comm

  #
  # Creates an instance of a socket using the supplied parameters.
  #
  def self.create(param)

    # Work around jRuby socket implementation issues
    if(RUBY_PLATFORM == 'java')
      return self.create_jruby(param)
    end

    case param.proto
      when 'tcp'
        return create_by_type(param, ::Socket::SOCK_STREAM, ::Socket::IPPROTO_TCP)
      when 'udp'
        return create_by_type(param, ::Socket::SOCK_DGRAM, ::Socket::IPPROTO_UDP)
      when 'ip'
        return create_ip(param)
      else
        raise Rex::UnsupportedProtocol.new(param.proto), caller
    end
  end

  #
  # Creates an instance of a socket using the supplied parameters.
  # Use various hacks to make this work with jRuby
  #
  def self.create_jruby(param)
    sock = nil

    # Notify handlers of the before socket create event.
    self.instance.notify_before_socket_create(self, param)

    case param.proto
      when 'tcp'
        if (param.server?)
          sock  = TCPServer.new(param.localport, param.localhost)
          klass = Rex::Socket::TcpServer
          if (param.ssl)
            klass = Rex::Socket::SslTcpServer
          end
          sock.extend(klass)

        else
          sock = TCPSocket.new(param.peerhost, param.peerport)
          klass = Rex::Socket::Tcp
          if (param.ssl)
            klass = Rex::Socket::SslTcp
          end
          sock.extend(klass)
        end
      when 'udp'
        if (param.server?)
          sock = UDPServer.new(param.localport, param.localhost)
          klass = Rex::Socket::UdpServer
          sock.extend(klass)
        else
          sock = UDPSocket.new(param.peerhost, param.peerport)
          klass = Rex::Socket::Udp
          sock.extend(klass)
        end
      else
        raise Rex::UnsupportedProtocol.new(param.proto), caller
    end

    sock.initsock(param)
    self.instance.notify_socket_created(self, sock, param)
    return sock
  end


  #
  # Creates a raw IP socket using the supplied Parameter instance.
  # Special-cased because of how different it is from UDP/TCP
  #
  def self.create_ip(param)
    self.instance.notify_before_socket_create(self, param)

    sock = ::Socket.open(::Socket::PF_INET, ::Socket::SOCK_RAW, ::Socket::IPPROTO_RAW)
    sock.setsockopt(::Socket::IPPROTO_IP, ::Socket::IP_HDRINCL, 1)

    # Configure broadcast support
    sock.setsockopt(::Socket::SOL_SOCKET, ::Socket::SO_BROADCAST, true)

    if (param.bare? == false)
      sock.extend(::Rex::Socket::Ip)
      sock.initsock(param)
    end

    self.instance.notify_socket_created(self, sock, param)

    sock
  end


  #
  # Creates a socket using the supplied Parameter instance.
  #
  def self.create_by_type(param, type, proto = 0)

    # Whether to use IPv6 addressing
    usev6 = false

    # Detect IPv6 addresses and enable IPv6 accordingly
    if ( Rex::Socket.support_ipv6?())

      # Allow the caller to force IPv6
      if (param.v6)
        usev6 = true
      end

      # Force IPv6 mode for non-connected UDP sockets
      if (type == ::Socket::SOCK_DGRAM and not param.peerhost)
        # FreeBSD allows IPv6 socket creation, but throws an error on sendto()
        # Windows 7 SP1 and newer also fail to sendto with IPv6 udp sockets
        unless Rex::Compat.is_freebsd or Rex::Compat.is_windows
          usev6 = true
        end
      end

      local = Rex::Socket.resolv_nbo(param.localhost) if param.localhost
      peer  = Rex::Socket.resolv_nbo(param.peerhost) if param.peerhost

      if (local and local.length == 16)
        usev6 = true
      end

      if (peer and peer.length == 16)
        usev6 = true
      end

      if (usev6)
        if (local and local.length == 4)
          if (local == "\x00\x00\x00\x00")
            param.localhost = '::'
          elsif (local == "\x7f\x00\x00\x01")
            param.localhost = '::1'
          else
            param.localhost = '::ffff:' + Rex::Socket.getaddress(param.localhost, true)
          end
        end

        if (peer and peer.length == 4)
          if (peer == "\x00\x00\x00\x00")
            param.peerhost = '::'
          elsif (peer == "\x7f\x00\x00\x01")
            param.peerhost = '::1'
          else
            param.peerhost = '::ffff:' + Rex::Socket.getaddress(param.peerhost, true)
          end
        end

        param.v6 = true
      end
    else
      # No IPv6 support
      param.v6 = false
    end

    # Notify handlers of the before socket create event.
    self.instance.notify_before_socket_create(self, param)

    # Create the socket
    sock = nil
    if (param.v6)
      sock = ::Socket.new(::Socket::AF_INET6, type, proto)
    else
      sock = ::Socket.new(::Socket::AF_INET, type, proto)
    end

    # Bind to a given local address and/or port if they are supplied
    if param.localport or param.localhost
      begin
        sock.setsockopt(::Socket::SOL_SOCKET, ::Socket::SO_REUSEADDR, true)
        sock.bind(Rex::Socket.to_sockaddr(param.localhost, param.localport))

      rescue ::Errno::EADDRNOTAVAIL,::Errno::EADDRINUSE
        sock.close
        raise Rex::AddressInUse.new(param.localhost, param.localport), caller
      end
    end

    # Configure broadcast support for all datagram sockets
    if (type == ::Socket::SOCK_DGRAM)
      sock.setsockopt(::Socket::SOL_SOCKET, ::Socket::SO_BROADCAST, true)
    end

    # If a server TCP instance is being created...
    if (param.server?)
      sock.listen(256)

      if (param.bare? == false)
        klass = Rex::Socket::TcpServer
        if (param.ssl)
          klass = Rex::Socket::SslTcpServer
        end
        sock.extend(klass)

        sock.initsock(param)
      end
    # Otherwise, if we're creating a client...
    else
      chain = []

      # If we were supplied with host information
      if (param.peerhost)

        # A flag that indicates whether we need to try multiple scopes
        retry_scopes = false

        # Always retry with link-local IPv6 addresses
        if Rex::Socket.is_ipv6?( param.peerhost ) and param.peerhost =~ /^fe80::/
          retry_scopes = true
        end

        # Prepare a list of scope IDs to try when connecting to
        # link-level addresses. Read from /proc if it is available,
        # otherwise increment through the first 255 IDs.
        @@ip6_lla_scopes ||= []

        if @@ip6_lla_scopes.length == 0 and retry_scopes

          # Linux specific interface lookup code
          if ::File.exists?( "/proc/self/net/igmp6" )
            ::File.open("/proc/self/net/igmp6") do |fd|
              fd.each_line do |line|
                line = line.strip
                tscope, tint, junk = line.split(/\s+/, 3)
                next if not tint

                # Specifying lo in any connect call results in the socket
                # being unusable, even if the correct interface is set.
                next if tint == "lo"

                @@ip6_lla_scopes << tscope
              end
            end
          else
          # Other Unix-like platforms should support a raw scope ID
            [*(1 .. 255)].map{ |x| @@ip6_lla_scopes << x.to_s }
          end
        end

        ip6_scope_idx = 0
        ip   = param.peerhost
        port = param.peerport

        if param.proxies
          chain = param.proxies.dup
          chain.push(['host',param.peerhost,param.peerport])
          ip = chain[0][1]
          port = chain[0][2].to_i
        end

        begin

          begin
            Timeout.timeout(param.timeout) do
              sock.connect(Rex::Socket.to_sockaddr(ip, port))
            end
          rescue ::Timeout::Error
            raise ::Errno::ETIMEDOUT
          end

        rescue ::Errno::EHOSTUNREACH,::Errno::ENETDOWN,::Errno::ENETUNREACH,::Errno::ENETRESET,::Errno::EHOSTDOWN,::Errno::EACCES,::Errno::EINVAL

          # Rescue errors caused by a bad Scope ID for a link-local address
          if retry_scopes and @@ip6_lla_scopes[ ip6_scope_idx ]
            ip = param.peerhost + "%" + @@ip6_lla_scopes[ ip6_scope_idx ]
            ip6_scope_idx += 1
            retry
          end

          sock.close
          raise Rex::HostUnreachable.new(param.peerhost, param.peerport), caller

        rescue ::Errno::EADDRNOTAVAIL,::Errno::EADDRINUSE
          sock.close
          raise Rex::AddressInUse.new(param.peerhost, param.peerport), caller

        rescue Errno::ETIMEDOUT
          sock.close
          raise Rex::ConnectionTimeout.new(param.peerhost, param.peerport), caller

        rescue ::Errno::ECONNRESET,::Errno::ECONNREFUSED,::Errno::ENOTCONN,::Errno::ECONNABORTED
          sock.close
          raise Rex::ConnectionRefused.new(param.peerhost, param.peerport), caller
        end
      end

      if (param.bare? == false)
        case param.proto
          when 'tcp'
            klass = Rex::Socket::Tcp
            sock.extend(klass)
            sock.initsock(param)
          when 'udp'
            sock.extend(Rex::Socket::Udp)
            sock.initsock(param)
        end
      end

      if chain.size > 1
        chain.each_with_index {
          |proxy, i|
          next_hop = chain[i + 1]
          if next_hop
            proxy(sock, proxy[0], next_hop[1], next_hop[2])
          end
        }
      end

      # Now extend the socket with SSL and perform the handshake
      if(param.bare? == false and param.ssl)
        klass = Rex::Socket::SslTcp
        sock.extend(klass)
        sock.initsock(param)
      end


    end

    # Notify handlers that a socket has been created.
    self.instance.notify_socket_created(self, sock, param)

    sock
  end

  def self.proxy(sock, type, host, port)
    case type.downcase
    when 'sapni'
      packet_type = 'NI_ROUTE'
      route_info_version = 2
      ni_version = 39
      num_of_entries = 2
      talk_mode = 1 # ref: http://help.sap.com/saphelp_dimp50/helpdata/En/f8/bb960899d743378ccb8372215bb767/content.htm
      num_rest_nodes = 1

      shost, sport = sock.peerinfo.split(":")
      first_route_item = [shost, 0, sport, 0, 0].pack("A*CA*cc")
      route_data = [first_route_item.length, first_route_item].pack("NA*")
      route_data << [host, 0, port.to_s, 0, 0].pack("A*CA*cc")

      ni_packet = [
        packet_type,
        0,
        route_info_version,
        ni_version,
        num_of_entries,
        talk_mode,
        0,
        0,
        num_rest_nodes
      ].pack("A8c8")
      # Add the data block, according to sap documentation:
      # A 4-byte header precedes each data block. These 4 bytes give the
      # length of the data block (length without leading 4 bytes)
      # The data block (the route data)
      ni_packet << [route_data.length - 4].pack('N') + route_data
      # Now that we've built the whole packet, prepend its length before writing it to the wire
      ni_packet = [ni_packet.length].pack('N') + ni_packet
      
      size = sock.put(ni_packet)
      
      if size != ni_packet.length
        raise Rex::ConnectionProxyError.new(host, port, type, "Failed to send the entire request to the proxy"), caller
      end

      begin
        ret_len = sock.get_once(4, 30).unpack('N')[0]
        if ret_len and ret_len != 0
          ret = sock.get_once(ret_len, 30)
        end
      rescue IOError
        raise Rex::ConnectionProxyError.new(host, port, type, "Failed to receive a response from the proxy"), caller
      end

      if ret and ret.length < 4
        raise Rex::ConnectionProxyError.new(host, port, type, "Failed to receive a complete response from the proxy"), caller
      end

      if ret =~ /NI_RTERR/
        case ret
        when /timed out/
          raise Rex::ConnectionProxyError.new(host, port, type, "Connection to remote host #{host} timed out")
        when /refused/
          raise Rex::ConnectionProxyError.new(host, port, type, "Connection to remote port #{port} closed")
        when /denied/
          raise Rex::ConnectionProxyError.new(host, port, type, "Connection to #{host}:#{port} blocked by ACL")
        else
          raise Rex::ConnectionProxyError.new(host, port, type, "Connection to #{host}:#{port} failed (Unknown fail)")
        end
      elsif ret =~ /NI_PONG/
        # success case
        # would like to print this "[*] remote native connection to #{host}:#{port} established\n"
      else
        raise Rex::ConnectionProxyError.new(host, port, type, "Connection to #{host}:#{port} failed (Unknown fail)")
      end

    when 'http'
      setup = "CONNECT #{host}:#{port} HTTP/1.0\r\n\r\n"
      size = sock.put(setup)
      if (size != setup.length)
        raise Rex::ConnectionProxyError.new(host, port, type, "Failed to send the entire request to the proxy"), caller
      end

      begin
        ret = sock.get_once(39,30)
      rescue IOError
        raise Rex::ConnectionProxyError.new(host, port, type, "Failed to receive a response from the proxy"), caller
      end

      if ret.nil?
        raise Rex::ConnectionProxyError.new(host, port, type, "Failed to receive a response from the proxy"), caller
      end

      resp = Rex::Proto::Http::Response.new
      resp.update_cmd_parts(ret.split(/\r?\n/)[0])

      if resp.code != 200
        raise Rex::ConnectionProxyError.new(host, port, type, "The proxy returned a non-OK response"), caller
      end
    when 'socks4'
      setup = [4,1,port.to_i].pack('CCn') + Socket.gethostbyname(host)[3] + Rex::Text.rand_text_alpha(rand(8)+1) + "\x00"
      size = sock.put(setup)
      if (size != setup.length)
        raise Rex::ConnectionProxyError.new(host, port, type, "Failed to send the entire request to the proxy"), caller
      end

      begin
        ret = sock.get_once(8, 30)
      rescue IOError
        raise Rex::ConnectionProxyError.new(host, port, type, "Failed to receive a response from the proxy"), caller
      end

      if (ret.nil? or ret.length < 8)
        raise Rex::ConnectionProxyError.new(host, port, type, "Failed to receive a complete response from the proxy"), caller
      end
      if ret[1,1] != "\x5a"
        raise Rex::ConnectionProxyError.new(host, port, type, "Proxy responded with error code #{ret[0,1].unpack("C")[0]}"), caller
      end
    when 'socks5'
      auth_methods = [5,1,0].pack('CCC')
      size = sock.put(auth_methods)
      if (size != auth_methods.length)
        raise Rex::ConnectionProxyError.new(host, port, type, "Failed to send the entire request to the proxy"), caller
      end
      ret = sock.get_once(2,30)
      if (ret[1,1] == "\xff")
        raise Rex::ConnectionProxyError.new(host, port, type, "The proxy requires authentication"), caller
      end

      if (Rex::Socket.is_ipv4?(host))
        addr = Rex::Socket.gethostbyname(host)[3]
        setup = [5,1,0,1].pack('C4') + addr + [port.to_i].pack('n')
      elsif (Rex::Socket.support_ipv6? and Rex::Socket.is_ipv6?(host))
        # IPv6 stuff all untested
        addr = Rex::Socket.gethostbyname(host)[3]
        setup = [5,1,0,4].pack('C4') + addr + [port.to_i].pack('n')
      else
        # Then it must be a domain name.
        # Unfortunately, it looks like the host has always been
        # resolved by the time it gets here, so this code never runs.
        setup = [5,1,0,3].pack('C4') + [host.length].pack('C') + host + [port.to_i].pack('n')
      end

      size = sock.put(setup)
      if (size != setup.length)
        raise Rex::ConnectionProxyError.new(host, port, type, "Failed to send the entire request to the proxy"), caller
      end

      begin
        response = sock.get_once(10, 30)
      rescue IOError
        raise Rex::ConnectionProxyError.new(host, port, type, "Failed to receive a response from the proxy"), caller
      end

      if (response.nil? or response.length < 10)
        raise Rex::ConnectionProxyError.new(host, port, type, "Failed to receive a complete response from the proxy"), caller
      end
      if response[1,1] != "\x00"
        raise Rex::ConnectionProxyError.new(host, port, type, "Proxy responded with error code #{response[1,1].unpack("C")[0]}"), caller
      end
    else
      raise RuntimeError, "The proxy type specified is not valid", caller
    end
  end

  ##
  #
  # Registration
  #
  ##

  def self.register_event_handler(handler) # :nodoc:
    self.instance.register_event_handler(handler)
  end

  def self.deregister_event_handler(handler) # :nodoc:
    self.instance.deregister_event_handler(handler)
  end

  def self.each_event_handler(handler) # :nodoc:
    self.instance.each_event_handler(handler)
  end

end
