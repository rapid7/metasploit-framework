# -*- coding: binary -*-

require 'rex/socket'
require 'net/ldap'

module Rex
module Proto
module LDAP

class Server
  attr_reader :serve_udp, :serve_tcp, :sock_options, :udp_sock, :tcp_sock, :syntax, :ldif
  module LdapClient
    attr_accessor :authenticated
    #
    # Initialize LDAP client state
    #
    def init_ldap_client
      self.authenticated = false
    end
  end

  class MockLdapClient
    attr_reader :peerhost, :peerport, :srvsock
    #
    # Create mock LDAP client
    #
    # @param host [String] PeerHost IP address
    # @param port [Fixnum] PeerPort integer
    # @param sock [Socket] Connection socket
    def initialize(host, port, sock)
      @peerhost = host
      @peerport = port
      @srvsock  = sock
    end

    #
    # Test method to prevent GC/ObjectSpace abuse via class lookups
    #
    def mock_ldap_client?
      true
    end

    def write(data)
      srvsock.sendto(data, peerhost, peerport)
    end
  end

  include Rex::IO::GramServer
  #
  # Create LDAP Server
  #
  # @param lhost [String] Listener address
  # @param lport [Fixnum] Listener port
  # @param udp [TrueClass, FalseClass] Listen on UDP socket
  # @param tcp [TrueClass, FalseClass] Listen on TCP socket
  # @param ldif [String] LDIF data
  # @param ctx [Hash] Framework context for sockets
  # @param dblock [Proc] Handler for :dispatch_request flow control interception
  # @param sblock [Proc] Handler for :send_response flow control interception
  #
  # @return [Rex::Proto::LDAP::Server] LDAP Server object
  def initialize(lhost = '0.0.0.0', lport = 389, udp = true, tcp = true, ldif = nil, comm = nil, ctx = {}, dblock = nil, sblock = nil)
    @serve_udp    = udp
    @serve_tcp    = tcp
    @sock_options = {
      'LocalHost' => lhost,
      'LocalPort' => lport,
      'Context'   => ctx,
      'Comm'      => comm
    }
    @ldif         = ldif
    self.listener_thread = nil
    self.dispatch_request_proc = dblock
    self.send_response_proc = sblock
  end

  #
  # Check if server is running
  #
  def running?
    self.listener_thread and self.listener_thread.alive?
  end

  #
  # Start the LDAP server
  #
  def start
    if self.serve_udp
      @udp_sock = Rex::Socket::Udp.create(self.sock_options)
      self.listener_thread = Rex::ThreadFactory.spawn("UDPLDAPServerListener", false) {
        monitor_listener
      }
    end

    if self.serve_tcp
      @tcp_sock = Rex::Socket::TcpServer.create(self.sock_options)
      self.tcp_sock.on_client_connect_proc = Proc.new { |cli|
        on_client_connect(cli)
      }
      self.tcp_sock.on_client_data_proc = Proc.new { |cli|
        on_client_data(cli)
      }
      # Close UDP socket if TCP socket fails
      begin
        self.tcp_sock.start
      rescue => e
        stop
        raise e
      end
      if !self.serve_udp
        self.listener_thread = tcp_sock.listener_thread
      end
    end

    self
  end

  #
  # Stop the LDAP server
  #
  def stop
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
  end

  #
  # Process client request, handled with dispatch_request_proc if set
  #
  # @param cli [Rex::Socket::Tcp, Rex::Socket::Udp] Client sending the request
  # @param data [String] raw LDAP request data
  def dispatch_request(cli, data)
    if self.dispatch_request_proc
      self.dispatch_request_proc.call(cli,data)
    else
      default_dispatch_request(cli,data)
    end
  end

  #
  # Default LDAP request dispatcher
  #
  # @param cli [Rex::Socket::Tcp, Rex::Socket::Udp] Client sending the request
  # @param data [String] raw LDAP request data
  def default_dispatch_request(cli, data)
    return if data.strip.empty?
    data.extend(Net::BER::Extensions::String)
    begin
      pdu = Net::LDAP::PDU.new(data.read_ber!(Net::LDAP::AsnSyntax))
      wlog("LDAP request has remaining data: #{data}") if data.length > 0
      resp = case pdu.app_tag
      when Net::LDAP::PDU::BindRequest # bind request
        cli.authenticated = true
        encode_ldap_response(
          pdu.message_id,
          Net::LDAP::ResultCodeSuccess,
          '',
          '',
          Net::LDAP::PDU::BindResult
        )
      when Net::LDAP::PDU::SearchRequest # search request
        if cli.authenticated
          # Perform query against some loaded LDIF structure
          treebase = pdu.search_parameters[:base_object].to_s
          # ... search, build packet, send to client
          encode_ldap_response(
            pdu.message_id,
            Net::LDAP::ResultCodeNoSuchObject, '',
            Net::LDAP::ResultStrings[Net::LDAP::ResultCodeNoSuchObject],
            Net::LDAP::PDU::SearchResult
          )
        else
          service.encode_ldap_response(pdu.message_id, 50, '', 'Not authenticated', Net::LDAP::PDU::SearchResult)
        end
      else
        service.encode_ldap_response(
          pdu.message_id,
          Net::LDAP::ResultCodeUnwillingToPerform,
          '',
          Net::LDAP::ResultStrings[Net::LDAP::ResultCodeUnwillingToPerform],
          Net::LDAP::PDU::SearchResult
        )      end
      resp.nil? ? cli.close : send_response(cli, resp)
    rescue => e
      elog(e)
      cli.close
      raise e
    end
  end

  #
  # Encode response for LDAP client consumption
  #
  # @param msgid [Integer] LDAP message identifier
  # @param code  [Integer] LDAP message code
  # @param dn    [String]  LDAP distinguished name
  # @param msg   [String]  LDAP response message
  # @param tag   [Integer] LDAP response tag
  #
  # @return [Net::BER::BerIdentifiedOid] LDAP query response
  def encode_ldap_response(msgid, code, dn, msg, tag)
    [
      msgid.to_ber,
      [
        code.to_ber_enumerated,
        dn.to_ber,
        msg.to_ber
      ].to_ber_appsequence(tag)
    ].to_ber_sequence
  end

  #
  # Search provided ldif data for query information
  #
  # @param filter [Net::LDAP::Filter] LDAP query filter
  # @param attrflt [Array, Symbol] LDAP attribute filter
  #
  # @return [Array] Query matches
  def search_ldif(filter, msgid, attrflt = :all)
    return [] if @ldif.nil? or @ldif.empty?
    ldif.map do |dn, entry|
      if filter.match(entry)
        attrs = []
        entry.each do |k, v|
          if attrflt == :all || attrflt.include?(k.downcase)
            attrvals = v.map(&:to_ber).to_ber_set
            attrs << [k.to_ber, attrvals].to_ber_sequence
          end
        end
        appseq = [
          dn.to_ber,
          attrs.to_ber_sequence
        ].to_ber_appsequence(Net::LDAP::PDU::SearchReturnedData)
        [msgid.to_ber, appseq].to_ber_sequence
      end
    end.compact
  end

  #
  # Returns the hardcore alias for the LDAP service
  #
  def self.hardcore_alias(*args)
    "#{(args[0] || '')}#{(args[1] || '')}"
  end

  #
  # LDAP server.
  #
  def alias
    "LDAP Server"
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
        cli = MockLdapClient.new(host, port, r[0])
        cli.extend(LdapClient)
        cli.init_ldap_client
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

  #
  # Extend client for LDAP state
  #
  def on_client_connect(cli)
    cli.extend(LdapClient)
    cli.init_ldap_client
  end

end

end
end
end
