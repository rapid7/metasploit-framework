module Msf
  # This mixin supports only HTTP fetch handlers.
  module Payload::Adapter::Fetch::Server::HTTP

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

    def add_resource(fetch_service, uri, srv_entry)
      vprint_status("Adding resource #{uri}")
      if fetch_service.resources.include?(uri)
        # When we clean up, we need to leave resources alone, because we never added one.
        fail_with(Msf::Exploit::Failure::BadConfig, 'Resource collision detected. Set FETCH_URIPATH to a different value to continue.')
      end
      begin
        fetch_service.add_resource(uri,
                                   'Proc' => proc do |cli, req|
                                   on_request_uri(cli, req, srv_entry)
                                   end,
                                   'VirtualDirectory' => true)
        @myresources << uri
      rescue ::Exception => e
        # When we clean up, we need to leave resources alone, because we never added one.
        fail_with(Msf::Exploit::Failure::Unknown, "Failed to add resource\n#{e}")
      end
    end

    def cleanup_http_fetch_service(fetch_service, my_resources)
      my_resources.each do |uri|
        if fetch_service.resources.include?(uri)
          fetch_service.remove_resource(uri)
        end
      end

      fetch_service = nil
    end

    def start_http_fetch_handler(srvname, ssl = false, ssl_cert = nil, ssl_compression = nil, ssl_cipher = nil, ssl_version = nil)
      # this looks a bit funny because I converted it to use an instance variable so that if we crash in the
      # middle and don't return a value, we still have the right fetch_service to clean up.
      fetch_service = start_http_server(ssl, ssl_cert, ssl_compression, ssl_cipher, ssl_version)
      if fetch_service.nil?
        cleanup_handler
        fail_with(Msf::Exploit::Failure::BadConfig, "Fetch handler failed to start on #{fetch_bindnetloc}")
      end
      vprint_status("#{fetch_protocol} server started")
      fetch_service.server_name = srvname
      fetch_service
    end

    def on_request_uri(cli, request, srv_entry)
      opts = srv_entry[:opts].dup
      client = cli.peerhost
      vprint_status("Client #{client} requested #{request.uri}")
      if (user_agent = request.headers['User-Agent'])
        client += " (#{user_agent})"
      end
      vprint_status("Sending payload to #{client}")
      if opts[:dynamic_arch]
        vprint_status("Dynamic Payload Detected, expecting a Query String in the request...")
        query_string = request.uri_parts['QueryString'] || {}
        arch_param = query_string['arch']
        if arch_param.nil? || arch_param.strip.empty?
          print_error('Fetch request missing required arch query parameter')
          cli.send_response(fetch_error_response(400, 'Bad Request'))
          return
        end
        arch = Rex::Arch.from_uname(arch_param)
        if arch_param == 'mips'
          print_warning("Detected 'mips' architecture using 'uname'. Normally, this means mipsbe, but it sometimes means mips[el|le].")
          print_warning('Serving a mipsbe payload. If the payload fails, retry with an explicit mipsle payload.')
        end
        if arch.nil?
          print_error("Failed to identify the architecture in Query String #{arch_param}")
          cli.send_response(fetch_error_response(404, 'Not Found'))
          return
        end
        vprint_status("Building payload for #{arch} arch")

        opts[:arch] = arch
        # Call generate with arch and dynamic_arch populated properly to build the right binary
        payload_exe = generate(opts)
        if payload_exe.nil?
          print_error("No payload available for #{arch}")
          cli.send_response(fetch_error_response(404, 'Not Found'))
        else
          cli.send_response(payload_response(payload_exe))
        end
      else
        cli.send_response(payload_response(srv_entry[:data]))
      end
    end

    def fetch_error_response(code, message)
      Rex::Proto::Http::Response.new(code, message, Rex::Proto::Http::DefaultProtocol)
    end

    def payload_response(srvexe)
      res = Rex::Proto::Http::Response.new(200, 'OK', Rex::Proto::Http::DefaultProtocol)
      res['Content-Type'] = 'text/html'
      res.body = srvexe.to_s.unpack('C*').pack('C*')
      res
    end

    def start_http_server(ssl = false, ssl_cert = nil, ssl_compression = nil, ssl_cipher = nil, ssl_version = nil)
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
end