# -*- coding: binary -*-
require 'rex/socket'
require 'rex/proto/http'
require 'rex/proto/http/handler'
require 'rex/proto/proxy/relay'

module Rex
module Proto
module Http

###
#
# Runtime extension of the HTTP clients that connect to the server.
#
###
module ProxyClient

  #
  # Initialize a new request instance.
  #
  def init_cli(server,resp_proc = nil)
    self.request   = Request.new
    self.server    = server
    self.keepalive = false
    self.session   = nil
  end

  #
  # Resets the parsing state.
  #
  def reset_cli
    self.request.reset
  end

  #
  # Transmits a response and adds the appropriate headers.
  #
  def send_response(response)
    # Set the connection to close or keep-alive depending on what the client
    # can support.
    response['Connection'] = (keepalive) ? 'Keep-Alive' : 'Close'

    # Send it off.
    put(response.to_s)
    close_session unless keepalive
  end

  def close_session
    self.session.close if self.session
    self.session = nil
  end

  #
  # The current request context.
  #
  attr_accessor :request
  #
  # Boolean that indicates whether or not the connection supports keep-alive.
  #
  attr_accessor :keepalive
  #
  # A reference to the server the client is associated with.
  #
  attr_accessor :server
  #
  # Reusable session for client
  #
  attr_accessor :session

end

module ConnectProxyRelay
  include Rex::Proto::Proxy::Relay

  def stop
    self.close unless self.closed?
  end
end

###
#
# Acts as an HTTP server, processing requests and dispatching them to
# registered procs.  Some of this server was modeled after webrick.
#
###
class Proxy

  include Proto

  #
  # Initializes an HTTP proxy as listening on the provided port and
  # hostname.
  #
  def initialize(listen_port = 80, listen_host = '0.0.0.0', ssl = false, context = {},
    comm = nil, ssl_cert = nil, proxies = nil, rewrite_proxy_headers = true,
    connect_host = nil, connect_port = nil
  )
    self.listen_host            = listen_host
    self.listen_port            = listen_port
    self.ssl                    = ssl
    self.context                = context
    self.comm                   = comm
    self.ssl_cert               = ssl_cert
    self.proxies                = proxies
    self.rewrite_proxy_headers  = rewrite_proxy_headers
    self.connect_host           = connect_host
    self.connect_port           = connect_port

    self.clients                = []
    self.listener               = nil
    self.req_handler            = nil
    self.res_handler            = nil
    self.connect_permit_cb      = nil
    self.redirect_limit         = 0
    self.request_timeout        = 30
    # If the keep-alive session is pushing to the client, monitor and forward the traffic
    # self.monitor_thread         = Rex::ThreadFactory.spawn("HTTP Proxy Monitor Thread", true) { monitor_clients }
  end

  #
  # Returns the hardcore alias for the HTTP proxy service
  #
  def self.hardcore_alias(*args)
    "#{args[0]}#{args[1]}"
  end

  #
  # HTTP server.
  #
  def alias
    super || "HTTP Proxy"
  end

  #
  # Listens on the defined port and host and starts monitoring for clients.
  #
  def start

    self.listener = Rex::Socket::TcpServer.create(
      'LocalHost' => self.listen_host,
      'LocalPort' => self.listen_port,
      'Context'   => self.context,
      'SSL'       => self.ssl,
      'SSLCert'   => self.ssl_cert,
      'Comm'      => self.comm
    )

    # Register callbacks
    self.listener.on_client_connect_proc = Proc.new { |cli|
      on_client_connect(cli)
    }
    self.listener.on_client_data_proc = Proc.new { |cli|
      on_client_data(cli)
    }

    self.listener.start
  end

  #
  # Terminates the monitor thread and turns off the listener.
  #
  def stop
    self.clients.map {|cli| cli.close_session}
    self.listener.stop
    self.listener.close
  end

  #
  # Waits for the HTTP service to terminate
  #
  def wait
    self.listener.wait if self.listener
  end

  #
  # Closes the supplied client, if valid.
  #
  def close_client(cli)
    cli.close_session
    listener.close_client(cli)
    self.clients.select! {|x| x != cli}
  end

  ##
  # Convenience methods for headers
  ##

  #
  # Adds Server headers if they dont exist
  #
  def add_headers(resp,headers)
    headers.each do |k,v|
      resp[k] = v unless resp[k]
    end
  end

  #
  # Replaces server headers only if exist
  #
  def sub_headers(resp,headers)
    headers.each do |k,v|
      resp[k] = v if resp[k]
    end
  end

  #
  # Puts in all headers, whether existing or not
  #
  def force_headers(resp,headers)
    add_response_headers(resp,headers)
    sub_response_headers(resp,headers)
  end

  #
  # Sends a 404 error to the client for a given request.
  #
  def send_e404(cli, request)
    resp = Response::E404.new

    resp['Content-Type'] = 'text/html'

    resp.body =
      "<html><head>" +
      "<title>404 Not Found</title>" +
      "</head><body>" +
      "<h1>Not found</h1>" +
      "The requested URL #{html_escape(request.resource)} was not found on this server.<p><hr>" +
      "</body></html>"

    # Send the response to the client like what
    cli.send_response(resp)
  end

  # Rewrite proxy elements of request to target request
  # Determine whether or not to use SSL for outbound
  def proxy_header_rewrite(request)
    return unless request.uri.match(/^http/i)

    # Determine if we need to use SSL
    request.headers['SSL'] = [443, 8443].any? {|e| request.headers['Host'] == e }
    # Rewrite URI HTTP request to headers and proper URI
    proxy_keys = request.headers.select {|key,val| key.match(/^proxy/i)}
    # Remove the proxy header info
    request.headers - proxy_keys
    # Rewrite the proxy specific options to our direct headers
    proxy_keys.each do |k,v|
      request.headers[k.sub(/^proxy-/i,'')] = v
    end
    normalize_request_target(request)
  end

  def normalize_request_target(request)
    # Extract host port and URI, map as appropriate, account for emtpy
    target = request.uri[/\/([\w\d\.:]+)/, 1]

    host,port = target.split(':')
    targ_uri = request.uri[/\/[\w\d\.]+(\/.*)/,1]
    request.uri = targ_uri || '/'

    # Check for DNS hostname
    if host.match(/\w+\.\w+/)
      request.headers['Vhost'] = host
      host = Rex::Socket.addr_itoa(
       Rex::Socket.gethostbyname( host )[3].unpack( 'N' ).first
      )
      request.headers['Host'] = port.nil? ? host : "#{host}:#{port}"
    else
      # Try an IPv6 configuration if host is not an IPv4 addr
      if !Rex::Socket.is_ipv4?(host)
        host = request.headers['Host'].reverse.split(':',2).last.reverse
        if !Rex::socket.is_ipv6?(host)
          raise ::Rex::ConnectionError('Cannot determine request target')
        end
      end
      # If we're here our host is valid, write the headers
      request.headers['Host'] = port.nil? ? host : "#{host}:#{port}"
    end
  end

  # Determine if redirect is valid
  def valid_redirect?(response)
    return ([301,302].any? {response.code} and response.headers['Location'])
  end

  attr_accessor :listen_port, :listen_host, :context, :ssl, :comm, :ssl_cert
  attr_accessor :listener, :proxies, :clients, :req_handler, :res_handler
  attr_accessor :redirect_limit, :rewrite_proxy_headers, :request_timeout
  attr_accessor :connect_host, :connect_port, :connect_permit_cb

protected

  #
  # Watches client connections for data, forwards back to client
  #
  def monitor_clients
    self.clients.each do |client|
      if client.session && (resp = client.session.read_response(2))
        client.send_response(resp)
      end
    end if
    Rex::ThreadSafe.sleep(2)
  end


  #
  # Extends new clients with the ServerClient module and initializes them.
  #
  def on_client_connect(cli)
    cli.extend(ProxyClient)

    cli.init_cli(self)
    self.clients << cli
  end

  #
  # Processes data coming in from a client.
  #
  def on_client_data(cli)
    begin
      # Handle CONNECT data
      if cli.is_a?(ConnectProxyRelay)
        while cli.has_read_data?(0.05)
          data = cli.read(65535)
          cli.session.put(data)
        end
        return
      end
      # Get our headers
      data = cli.read(65535)

      raise ::EOFError if (not data || data.empty?)

      case cli.request.parse(data)
        when Packet::ParseCode::Completed
          dispatch_request(cli, cli.request)
          cli.reset_cli

        when Packet::ParseCode::Partial
          # The proxy needs the whole request
          content_len = cli.request.headers['Content-Length'] || 0
          loop do
            line = cli.readline
            if line =~ /^Content-Length:\s+(\d+)\s*$/
              content_len = $1.to_i
            end

            if line.strip.empty?
              # Read and parse the content length into our request
              if content_len >= 0
                cli.request.parse(cli.read(content_len))
              end

              break
            else
              cli.request.parse(line)
            end
          end
          cli.reset_cli

        when Packet::ParseCode::Error
          close_client(cli)
      end
    rescue EOFError
      if (cli.request.completed?)
        dispatch_request(cli, cli.request)

        cli.reset_cli
      end

      close_client(cli)
      self.clients.delete(cli)
    end
  end

  #
  # Dispatches the supplied request for a given connection.
  # Provides hooks for actions on data, returns if action closed client
  #
  def dispatch_request(cli, request)

    # Is the client requesting keep-alive?
    %w{Proxy-Connection Connection}.each do |key|
      if request[key] and request[key].downcase == 'Keep-Alive'.downcase
        cli.keepalive = true
      end
    end

    # Proxy header rewrite
    if self.rewrite_proxy_headers
      proxy_header_rewrite(request)
    end

    # Do something with the request before we pass it on
    if self.req_handler
      self.req_handler.call(cli, request)
      return if cli.closed?
    end

    # Get server response to client request
    begin
      response = proxy_request(cli,request.dup)
      # Follow redirects if allowed
      if valid_redirect?(response) and self.redirect_limit > 0
        count_redir = self.redirect_limit
        while valid_redirect?(response) and count_redir > 0 do

          re_request = request.dup
          re_request.headers

          re_request.uri = response.headers['Location']
          # Set cookie as needed
          if response.headers['Set-Cookie']
            re_request.headers['Cookie'] = response.headers['Set-Cookie']
          end
          normalize_request_target(request)

          if response.headers['Location'].scan(/^\w+/).first.downcase == 'https'
            re_request.headers['SSL'] = true
          end

          response = proxy_request(cli,re_request)
          count_redir -= 1
        end
      end

    rescue ::Rex::ConnectionError
      send_e404(cli)
      close_client(cli)
      return
    end

    # Do something with the response before returning it
    if self.res_handler
      self.res_handler.call(cli,response)
      return if cli.closed?
    end

    cli.send_response(response)

    # If keep-alive isn't enabled for this client, close the connection
    if (cli.keepalive == false)
      close_client(cli)
    end
  end

  #
  # Send request to server, return response
  # Attempt to use existing session
  # Final header modifications on rewrite
  #
  def proxy_request(cli, request, timeout = nil)

    timeout ||= self.request_timeout
    opts = request.headers
    host,port = opts['Host'].split(':')
    host = self.connect_host if self.connect_host
    port = self.connect_port if self.connect_port
    if port.nil? or port == 0
      port = (opts['SSL'] || self.ssl) ? 443 : 80
    end

    # Address TCP tunnels over the proxy
    if request.method == 'CONNECT'
      if permit_connect?(*cli.peerinfo.split(':'), host, port.to_s)
        begin
          cli.session = Rex::Socket::Tcp.create(
            'PeerHost' => host,
            'PeerPort' => port,
            'Context'  => self.context,
            'Proxies'  => self.proxies
          )
        rescue => e
          cli.close_session
          send_e404(cli)
          raise ::Rex::ConnectionError(e)
        end
        cli.keepalive = true
        cli.extend(ConnectProxyRelay)
        cli.relay(cli, cli.session, "HTTPConnectProxyRelay")
        resp = Rex::Proto::Http::Response.new(204)
        resp.auto_cl = false
        return resp
      else
        cli.keepalive = false
        resp = Rex::Proto::Http::Response.new(405, 'Method Not Allowed')
        resp['Allow'] = 'OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST'
        resp.auto_cl = false
        return resp
      end
    end
    # Remove encoding mechanisms we dont support
    if opts['Accept-Encoding']
      acc_enc = opts['Accept-Encoding'].split(',').select {|x| x =~ /gzip|deflate|none/i}.join(',')
      opts['Accept-Encoding'] = acc_enc
    end

    ssl = opts.delete('SSL')
    ssl ||= self.ssl
    # Build client session unless we have a live one
    cli.session =  Rex::Proto::Http::Client.new(
      host,
      port,
      self.context,
      # TODO: allow proxying of SSL -> Plain Text and reverse
      ssl,
      # self.ssl_version,
      self.proxies
      # TODO: Add user/pass for HTTP auth
    ) unless cli.session and cli.session.conn? and cli.session.send(:hostname).strip == opts['Vhost'].strip

    # Configure the session
    cli.session.set_config(
      'vhost'             => opts['Vhost'],
      'agent'             => opts['UserAgent'],
      'transfer_chunked'  => opts['Transfer-Encoding'],
      'read_max_data'     => (1024*1024)
    )
    # Dont send confusing IPs to reverse proxies at the edge
    opts['Host'] = opts['Vhost'] if opts['Vhost'] and !opts['Vhost'].strip.empty?
    # Send request to the server, get response
    # Persist request if keep-alive
    # Send 404 if we fail
    begin
      response = cli.session.send_recv(request, opts[:timeout] ? opts[:timeout] : timeout, cli.keepalive)
    rescue => e
      cli.close_session
      send_e404(cli)
      raise ::Rex::ConnectionError(e)
    end
    return response
  end

  def permit_connect?(saddr, sport, daddr, dport)
    return true if self.connect_permit_cb.nil?
    self.connect_permit_cb.call(saddr, sport, daddr, dport)
  end
end

end
end
end
