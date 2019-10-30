# -*- coding: binary -*-
require 'rex/socket'
require 'rex/proto/http'
require 'rex/text'
require 'digest'

require 'rex/proto/http/client_request'

module Rex
module Proto
module Http

###
#
# Acts as a client to an HTTP server, sending requests and receiving responses.
#
# See the RFC: http://www.w3.org/Protocols/rfc2616/rfc2616.html
#
###
class Client

  DefaultUserAgent = ClientRequest::DefaultUserAgent

  #
  # Creates a new client instance
  #
  def initialize(host, port = 80, context = {}, ssl = nil, ssl_version = nil, proxies = nil, username = '', password = '')
    self.hostname = host
    self.port     = port.to_i
    self.context  = context
    self.ssl      = ssl
    self.ssl_version = ssl_version
    self.proxies  = proxies
    self.username = username
    self.password = password

    # Take ClientRequest's defaults, but override with our own
    self.config = Http::ClientRequest::DefaultConfig.merge({
      'read_max_data'   => (1024*1024*1),
      'vhost'           => self.hostname,
    })

    # XXX: This info should all be controlled by ClientRequest
    self.config_types = {
      'uri_encode_mode'        => ['hex-normal', 'hex-all', 'hex-random', 'u-normal', 'u-random', 'u-all'],
      'uri_encode_count'       => 'integer',
      'uri_full_url'           => 'bool',
      'pad_method_uri_count'   => 'integer',
      'pad_uri_version_count'  => 'integer',
      'pad_method_uri_type'    => ['space', 'tab', 'apache'],
      'pad_uri_version_type'   => ['space', 'tab', 'apache'],
      'method_random_valid'    => 'bool',
      'method_random_invalid'  => 'bool',
      'method_random_case'     => 'bool',
      'version_random_valid'   => 'bool',
      'version_random_invalid' => 'bool',
      'uri_dir_self_reference' => 'bool',
      'uri_dir_fake_relative'  => 'bool',
      'uri_use_backslashes'    => 'bool',
      'pad_fake_headers'       => 'bool',
      'pad_fake_headers_count' => 'integer',
      'pad_get_params'         => 'bool',
      'pad_get_params_count'   => 'integer',
      'pad_post_params'        => 'bool',
      'pad_post_params_count'  => 'integer',
      'uri_fake_end'           => 'bool',
      'uri_fake_params_start'  => 'bool',
      'header_folding'         => 'bool',
      'chunked_size'           => 'integer'
    }


  end

  #
  # Set configuration options
  #
  def set_config(opts = {})
    opts.each_pair do |var,val|
      # Default type is string
      typ = self.config_types[var] || 'string'

      # These are enum types
      if typ.is_a?(Array)
        if not typ.include?(val)
          raise RuntimeError, "The specified value for #{var} is not one of the valid choices"
        end
      end

      # The caller should have converted these to proper ruby types, but
      # take care of the case where they didn't before setting the
      # config.

      if(typ == 'bool')
        val = (val =~ /^(t|y|1)$/i ? true : false || val === true)
      end

      if(typ == 'integer')
        val = val.to_i
      end

      self.config[var]=val
    end
  end

  #
  # Create an arbitrary HTTP request
  #
  # @param opts [Hash]
  # @option opts 'agent'         [String] User-Agent header value
  # @option opts 'connection'    [String] Connection header value
  # @option opts 'cookie'        [String] Cookie header value
  # @option opts 'data'          [String] HTTP data (only useful with some methods, see rfc2616)
  # @option opts 'encode'        [Bool]   URI encode the supplied URI, default: false
  # @option opts 'headers'       [Hash]   HTTP headers, e.g. <code>{ "X-MyHeader" => "value" }</code>
  # @option opts 'method'        [String] HTTP method to use in the request, not limited to standard methods defined by rfc2616, default: GET
  # @option opts 'proto'         [String] protocol, default: HTTP
  # @option opts 'query'         [String] raw query string
  # @option opts 'raw_headers'   [Hash]   HTTP headers
  # @option opts 'uri'           [String] the URI to request
  # @option opts 'version'       [String] version of the protocol, default: 1.1
  # @option opts 'vhost'         [String] Host header value
  #
  # @return [ClientRequest]
  def request_raw(opts={})
    opts = self.config.merge(opts)

    opts['ssl']         = self.ssl
    opts['cgi']         = false
    opts['port']        = self.port

    req = ClientRequest.new(opts)
  end


  #
  # Create a CGI compatible request
  #
  # @param (see #request_raw)
  # @option opts (see #request_raw)
  # @option opts 'ctype'         [String] Content-Type header value, default: +application/x-www-form-urlencoded+
  # @option opts 'encode_params' [Bool]   URI encode the GET or POST variables (names and values), default: true
  # @option opts 'vars_get'      [Hash]   GET variables as a hash to be translated into a query string
  # @option opts 'vars_post'     [Hash]   POST variables as a hash to be translated into POST data
  #
  # @return [ClientRequest]
  def request_cgi(opts={})
    opts = self.config.merge(opts)

    opts['ctype']       ||= 'application/x-www-form-urlencoded'
    opts['ssl']         = self.ssl
    opts['cgi']         = true
    opts['port']        = self.port

    req = ClientRequest.new(opts)
    req
  end

  #
  # Connects to the remote server if possible.
  #
  # @param t [Integer] Timeout
  # @see Rex::Socket::Tcp.create
  # @return [Rex::Socket::Tcp]
  def connect(t = -1)
    # If we already have a connection and we aren't pipelining, close it.
    if (self.conn)
      if !pipelining?
        close
      else
        return self.conn
      end
    end

    timeout = (t.nil? or t == -1) ? 0 : t

    self.conn = Rex::Socket::Tcp.create(
      'PeerHost'   => self.hostname,
      'PeerPort'   => self.port.to_i,
      'LocalHost'  => self.local_host,
      'LocalPort'  => self.local_port,
      'Context'    => self.context,
      'SSL'        => self.ssl,
      'SSLVersion' => self.ssl_version,
      'Proxies'    => self.proxies,
      'Timeout'    => timeout
    )
  end

  #
  # Closes the connection to the remote server.
  #
  def close
    if self.conn && !self.conn.closed?
      self.conn.shutdown
      self.conn.close
    end

    self.conn = nil
  end

  #
  # Sends a request and gets a response back
  #
  # If the request is a 401, and we have creds, it will attempt to complete
  # authentication and return the final response
  #
  # @return (see #_send_recv)
  def send_recv(req, t = -1, persist = false, opts = {})
    res = _send_recv(req, t, persist, opts)
    if res and res.code == 401 and res.headers['WWW-Authenticate']
      res = send_auth(res, req.opts, t, persist)
    end
    res
  end

  #
  # Transmit an HTTP request and receive the response
  #
  # If persist is set, then the request will attempt to reuse an existing
  # connection.
  #
  # Call this directly instead of {#send_recv} if you don't want automatic
  # authentication handling.
  #
  # @return (see #read_response)
  def _send_recv(req, t = -1, persist = false, opts = {})
    @pipeline = persist
    send_request(req, t)
    res = read_response(t, opts)
    res.request = req.to_s if res
    res.peerinfo = peerinfo if res
    res
  end

  #
  # Send an HTTP request to the server
  #
  # @param req [Request,ClientRequest,#to_s] The request to send
  # @param t (see #connect)
  #
  # @return [void]
  def send_request(req, t = -1)
    connect(t)
    conn.put(req.to_s)
  end

  # Resends an HTTP Request with the propper authentcation headers
  # set. If we do not support the authentication type the server requires
  # we return the original response object
  #
  # @param res [Response] the HTTP Response object
  # @param opts [Hash] the options used to generate the original HTTP request
  # @param t [Integer] the timeout for the request in seconds
  # @param persist [Boolean] whether or not to persist the TCP connection (pipelining)
  #
  # @return [Response] the last valid HTTP response object we received
  def send_auth(res, opts, t, persist)
    if opts['username'].nil? or opts['username'] == ''
      if self.username and not (self.username == '')
        opts['username'] = self.username
        opts['password'] = self.password
      else
        opts['username'] = nil
        opts['password'] = nil
      end
    end

    return res if opts['username'].nil? or opts['username'] == ''
    supported_auths = res.headers['WWW-Authenticate']

    # if several providers are available, the client may want one in particular
    preferred_auth = opts['preferred_auth']

    if supported_auths.include?('Basic') && (preferred_auth.nil? || preferred_auth == 'Basic')
      opts['headers'] ||= {}
      opts['headers']['Authorization'] = basic_auth_header(opts['username'],opts['password'] )
      req = request_cgi(opts)
      res = _send_recv(req,t,persist)
      return res
    elsif supported_auths.include?('Digest') && (preferred_auth.nil? || preferred_auth == 'Digest')
      temp_response = digest_auth(opts)
      if temp_response.kind_of? Rex::Proto::Http::Response
        res = temp_response
      end
      return res
    elsif supported_auths.include?('NTLM') && (preferred_auth.nil? || preferred_auth == 'NTLM')
      opts['provider'] = 'NTLM'
      temp_response = negotiate_auth(opts)
      if temp_response.kind_of? Rex::Proto::Http::Response
        res = temp_response
      end
      return res
    elsif supported_auths.include?('Negotiate') && (preferred_auth.nil? || preferred_auth == 'Negotiate')
      opts['provider'] = 'Negotiate'
      temp_response = negotiate_auth(opts)
      if temp_response.kind_of? Rex::Proto::Http::Response
        res = temp_response
      end
      return res
    end
    return res
  end

  # Converts username and password into the HTTP Basic authorization
  # string.
  #
  # @return [String] A value suitable for use as an Authorization header
  def basic_auth_header(username,password)
    auth_str = username.to_s + ":" + password.to_s
    auth_str = "Basic " + Rex::Text.encode_base64(auth_str)
  end


  def make_cnonce
    Digest::MD5.hexdigest "%x" % (Time.now.to_i + rand(65535))
  end

  # Send a series of requests to complete Digest Authentication
  #
  # @param opts [Hash] the options used to build an HTTP request
  # @return [Response] the last valid HTTP response we received
  def digest_auth(opts={})
    cnonce = make_cnonce
    nonce_count = 0

    to = opts['timeout'] || 20

    digest_user = opts['username'] || ""
    digest_password =  opts['password'] || ""

    method = opts['method']
    path = opts['uri']
    iis = true
    if (opts['DigestAuthIIS'] == false or self.config['DigestAuthIIS'] == false)
      iis = false
    end

    begin
    nonce_count += 1

    resp = opts['response']

    if not resp
      # Get authentication-challenge from server, and read out parameters required
      r = request_cgi(opts.merge({
          'uri' => path,
          'method' => method }))
      resp = _send_recv(r, to)
      unless resp.kind_of? Rex::Proto::Http::Response
        return nil
      end

      if resp.code != 401
        return resp
      end
      return resp unless resp.headers['WWW-Authenticate']
    end

    # Don't anchor this regex to the beginning of string because header
    # folding makes it appear later when the server presents multiple
    # WWW-Authentication options (such as is the case with IIS configured
    # for Digest or NTLM).
    resp['www-authenticate'] =~ /Digest (.*)/

    parameters = {}
    $1.split(/,[[:space:]]*/).each do |p|
      k, v = p.split("=", 2)
      parameters[k] = v.gsub('"', '')
    end

    qop = parameters['qop']

    if parameters['algorithm'] =~ /(.*?)(-sess)?$/
      algorithm = case $1
      when 'MD5' then Digest::MD5
      when 'SHA1' then Digest::SHA1
      when 'SHA2' then Digest::SHA2
      when 'SHA256' then Digest::SHA256
      when 'SHA384' then Digest::SHA384
      when 'SHA512' then Digest::SHA512
      when 'RMD160' then Digest::RMD160
      else raise Error, "unknown algorithm \"#{$1}\""
      end
      algstr = parameters["algorithm"]
      sess = $2
    else
      algorithm = Digest::MD5
      algstr = "MD5"
      sess = false
    end

    a1 = if sess then
      [
        algorithm.hexdigest("#{digest_user}:#{parameters['realm']}:#{digest_password}"),
        parameters['nonce'],
        cnonce
      ].join ':'
    else
      "#{digest_user}:#{parameters['realm']}:#{digest_password}"
    end

    ha1 = algorithm.hexdigest(a1)
    ha2 = algorithm.hexdigest("#{method}:#{path}")

    request_digest = [ha1, parameters['nonce']]
    request_digest.push(('%08x' % nonce_count), cnonce, qop) if qop
    request_digest << ha2
    request_digest = request_digest.join ':'

    # Same order as IE7
    auth = [
      "Digest username=\"#{digest_user}\"",
      "realm=\"#{parameters['realm']}\"",
      "nonce=\"#{parameters['nonce']}\"",
      "uri=\"#{path}\"",
      "cnonce=\"#{cnonce}\"",
      "nc=#{'%08x' % nonce_count}",
      "algorithm=#{algstr}",
      "response=\"#{algorithm.hexdigest(request_digest)[0, 32]}\"",
      # The spec says the qop value shouldn't be enclosed in quotes, but
      # some versions of IIS require it and Apache accepts it.  Chrome
      # and Firefox both send it without quotes but IE does it this way.
      # Use the non-compliant-but-everybody-does-it to be as compatible
      # as possible by default.  The user can override if they don't like
      # it.
      if qop.nil? then
      elsif iis then
        "qop=\"#{qop}\""
      else
        "qop=#{qop}"
      end,
      if parameters.key? 'opaque' then
        "opaque=\"#{parameters['opaque']}\""
      end
    ].compact

    headers ={ 'Authorization' => auth.join(', ') }
    headers.merge!(opts['headers']) if opts['headers']

    # Send main request with authentication
    r = request_cgi(opts.merge({
      'uri' => path,
      'method' => method,
      'headers' => headers }))
    resp = _send_recv(r, to, true)
    unless resp.kind_of? Rex::Proto::Http::Response
      return nil
    end

    return resp

    rescue ::Errno::EPIPE, ::Timeout::Error
    end
  end

  #
  # Builds a series of requests to complete Negotiate Auth. Works essentially
  # the same way as Digest auth. Same pipelining concerns exist.
  #
  # @option opts (see #send_request_cgi)
  # @option opts provider ["Negotiate","NTLM"] What Negotiate provider to use
  #
  # @return [Response] the last valid HTTP response we received
  def negotiate_auth(opts={})

    to = opts['timeout'] || 20
    opts['username'] ||= ''
    opts['password'] ||= ''

    if opts['provider'] and opts['provider'].include? 'Negotiate'
      provider = "Negotiate "
    else
      provider = "NTLM "
    end

    opts['method']||= 'GET'
    opts['headers']||= {}

    workstation_name = Rex::Text.rand_text_alpha(rand(8)+6)
    domain_name = self.config['domain']

    ntlm_client = ::Net::NTLM::Client.new(
      opts['username'],
      opts['password'],
      workstation: workstation_name,
      domain: domain_name,
    )
    type1 = ntlm_client.init_context

    begin
      # First request to get the challenge
      opts['headers']['Authorization'] = provider + type1.encode64

      r = request_cgi(opts)
      resp = _send_recv(r, to)
      unless resp.kind_of? Rex::Proto::Http::Response
        return nil
      end

      return resp unless resp.code == 401 && resp.headers['WWW-Authenticate']

      # Get the challenge and craft the response
      ntlm_challenge = resp.headers['WWW-Authenticate'].scan(/#{provider}([A-Z0-9\x2b\x2f=]+)/ni).flatten[0]
      return resp unless ntlm_challenge

      ntlm_message_3 = ntlm_client.init_context(ntlm_challenge)

      # Send the response
      opts['headers']['Authorization'] = "#{provider}#{ntlm_message_3.encode64}"
      r = request_cgi(opts)
      resp = _send_recv(r, to, true)
      unless resp.kind_of? Rex::Proto::Http::Response
        return nil
      end
      return resp

    rescue ::Errno::EPIPE, ::Timeout::Error
      return nil
    end
  end

  #
  # Read a response from the server
  #
  # Wait at most t seconds for the full response to be read in.
  # If t is specified as a negative value, it indicates an indefinite wait cycle.
  # If t is specified as nil or 0, it indicates no response parsing is required.
  #
  # @return [Response]
  def read_response(t = -1, opts = {})
    # Return a nil response if timeout is nil or 0
    return if t.nil? || t == 0

    resp = Response.new
    resp.max_data = config['read_max_data']

    Timeout.timeout((t < 0) ? nil : t) do

      rv = nil
      while (
               not conn.closed? and
               rv != Packet::ParseCode::Completed and
               rv != Packet::ParseCode::Error
              )

        begin

          buff = conn.get_once(resp.max_data, 1)
          rv   = resp.parse(buff || '')

        # Handle unexpected disconnects
        rescue ::Errno::EPIPE, ::EOFError, ::IOError
          case resp.state
          when Packet::ParseState::ProcessingHeader
            resp = nil
          when Packet::ParseState::ProcessingBody
            # truncated request, good enough
            resp.error = :truncated
          end
          break
        end

        # This is a dirty hack for broken HTTP servers
        if rv == Packet::ParseCode::Completed
          rbody = resp.body
          rbufq = resp.bufq

          rblob = rbody.to_s + rbufq.to_s
          tries = 0
          begin
            # XXX: This doesn't deal with chunked encoding or "Content-type: text/html; charset=..."
            while tries < 1000 and resp.headers["Content-Type"]== "text/html" and rblob !~ /<\/html>/i
              buff = conn.get_once(-1, 0.05)
              break if not buff
              rblob += buff
              tries += 1
            end
          rescue ::Errno::EPIPE, ::EOFError, ::IOError
          end

          resp.bufq = ""
          resp.body = rblob
        end
      end
    end

    return resp if not resp

    # As a last minute hack, we check to see if we're dealing with a 100 Continue here.
    # Most of the time this is handled by the parser via check_100()
    if resp.proto == '1.1' and resp.code == 100 and not opts[:skip_100]
      # Read the real response from the body if we found one
      # If so, our real response became the body, so we re-parse it.
      if resp.body.to_s =~ /^HTTP/
        body = resp.body
        resp = Response.new
        resp.max_data = config['read_max_data']
        rv = resp.parse(body)
      # We found a 100 Continue but didn't read the real reply yet
      # Otherwise reread the reply, but don't try this hack again
      else
        resp = read_response(t, :skip_100 => true)
      end
    end

    resp
  rescue Timeout::Error
    # Allow partial response due to timeout
    resp if opts['partial']
  end

  #
  # Cleans up any outstanding connections and other resources.
  #
  def stop
    close
  end

  #
  # Returns whether or not the conn is valid.
  #
  def conn?
    conn != nil
  end

  #
  # Whether or not connections should be pipelined.
  #
  def pipelining?
    pipeline
  end

  #
  # Target host addr and port for this connection
  #
  def peerinfo
    if self.conn
      pi = self.conn.peerinfo || nil
      if pi
        return {
          'addr' => pi.split(':')[0],
          'port' => pi.split(':')[1].to_i
        }
      end
    end
    nil
  end

  #
  # The client request configuration
  #
  attr_accessor :config
  #
  # The client request configuration classes
  #
  attr_accessor :config_types
  #
  # Whether or not pipelining is in use.
  #
  attr_accessor :pipeline
  #
  # The local host of the client.
  #
  attr_accessor :local_host
  #
  # The local port of the client.
  #
  attr_accessor :local_port
  #
  # The underlying connection.
  #
  attr_accessor :conn
  #
  # The calling context to pass to the socket
  #
  attr_accessor :context
  #
  # The proxy list
  #
  attr_accessor :proxies

  # Auth
  attr_accessor :username, :password

  # When parsing the request, thunk off the first response from the server, since junk
  attr_accessor :junk_pipeline

protected

  # https
  attr_accessor :ssl, :ssl_version # :nodoc:

  attr_accessor :hostname, :port # :nodoc:

end

end
end
end
