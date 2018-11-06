# frozen_string_literal: false
# xmlrpc/client.rb
# Copyright (C) 2001, 2002, 2003 by Michael Neumann (mneumann@ntecs.de)
#
# Released under the same term of license as Ruby.
#
# History
#   $Id$
#
require "xmlrpc/parser"
require "xmlrpc/create"
require "xmlrpc/config"
require "xmlrpc/utils"     # ParserWriterChooseMixin
require "net/http"
require "uri"

module XMLRPC # :nodoc:

  # Provides remote procedure calls to a XML-RPC server.
  #
  # After setting the connection-parameters with XMLRPC::Client.new which
  # creates a new XMLRPC::Client instance, you can execute a remote procedure
  # by sending the XMLRPC::Client#call or XMLRPC::Client#call2
  # message to this new instance.
  #
  # The given parameters indicate which method to call on the remote-side and
  # of course the parameters for the remote procedure.
  #
  #     require "xmlrpc/client"
  #
  #     server = XMLRPC::Client.new("www.ruby-lang.org", "/RPC2", 80)
  #     begin
  #       param = server.call("michael.add", 4, 5)
  #       puts "4 + 5 = #{param}"
  #     rescue XMLRPC::FaultException => e
  #       puts "Error:"
  #       puts e.faultCode
  #       puts e.faultString
  #     end
  #
  # or
  #
  #     require "xmlrpc/client"
  #
  #     server = XMLRPC::Client.new("www.ruby-lang.org", "/RPC2", 80)
  #     ok, param = server.call2("michael.add", 4, 5)
  #     if ok then
  #       puts "4 + 5 = #{param}"
  #     else
  #       puts "Error:"
  #       puts param.faultCode
  #       puts param.faultString
  #     end
  class Client

    USER_AGENT = "XMLRPC::Client (Ruby #{RUBY_VERSION})"

    include ParserWriterChooseMixin
    include ParseContentType


    # Creates an object which represents the remote XML-RPC server on the
    # given +host+. If the server is CGI-based, +path+ is the
    # path to the CGI-script, which will be called, otherwise (in the
    # case of a standalone server) +path+ should be <tt>"/RPC2"</tt>.
    # +port+ is the port on which the XML-RPC server listens.
    #
    # If +proxy_host+ is given, then a proxy server listening at
    # +proxy_host+ is used. +proxy_port+ is the port of the
    # proxy server.
    #
    # Default values for +host+, +path+ and +port+ are 'localhost', '/RPC2' and
    # '80' respectively using SSL '443'.
    #
    # If +user+ and +password+ are given, each time a request is sent,
    # an Authorization header is sent. Currently only Basic Authentication is
    # implemented, no Digest.
    #
    # If +use_ssl+ is set to +true+, communication over SSL is enabled.
    #
    # Parameter +timeout+ is the time to wait for a XML-RPC response, defaults to 30.
    def initialize(host=nil, path=nil, port=nil, proxy_host=nil, proxy_port=nil,
                   user=nil, password=nil, use_ssl=nil, timeout=nil)

      @http_header_extra = nil
      @http_last_response = nil
      @cookie = nil

      @host       = host || "localhost"
      @path       = path || "/RPC2"
      @proxy_host = proxy_host
      @proxy_port = proxy_port
      @proxy_host ||= 'localhost' if @proxy_port != nil
      @proxy_port ||= 8080 if @proxy_host != nil
      @use_ssl    = use_ssl || false
      @timeout    = timeout || 30

      if use_ssl
        require "net/https"
        @port = port || 443
      else
        @port = port || 80
      end

      @user, @password = user, password

      set_auth

      # convert ports to integers
      @port = @port.to_i if @port != nil
      @proxy_port = @proxy_port.to_i if @proxy_port != nil

      # HTTP object for synchronous calls
      @http = net_http(@host, @port, @proxy_host, @proxy_port)
      @http.use_ssl = @use_ssl if @use_ssl
      @http.read_timeout = @timeout
      @http.open_timeout = @timeout

      @parser = nil
      @create = nil
    end


    class << self

    # Creates an object which represents the remote XML-RPC server at the
    # given +uri+. The URI should have a host, port, path, user and password.
    # Example: https://user:password@host:port/path
    #
    # Raises an ArgumentError if the +uri+ is invalid,
    # or if the protocol isn't http or https.
    #
    # If a +proxy+ is given it should be in the form of "host:port".
    #
    # The optional +timeout+ defaults to 30 seconds.
    def new2(uri, proxy=nil, timeout=nil)
      begin
        url = URI(uri)
      rescue URI::InvalidURIError => e
        raise ArgumentError, e.message, e.backtrace
      end

      unless URI::HTTP === url
        raise ArgumentError, "Wrong protocol specified. Only http or https allowed!"
      end

      proto  = url.scheme
      user   = url.user
      passwd = url.password
      host   = url.host
      port   = url.port
      path   = url.path.empty? ? nil : url.request_uri

      proxy_host, proxy_port = (proxy || "").split(":")
      proxy_port = proxy_port.to_i if proxy_port

      self.new(host, path, port, proxy_host, proxy_port, user, passwd, (proto == "https"), timeout)
    end

    alias new_from_uri new2

    # Receives a Hash and calls XMLRPC::Client.new
    # with the corresponding values.
    #
    # The +hash+ parameter has following case-insensitive keys:
    # * host
    # * path
    # * port
    # * proxy_host
    # * proxy_port
    # * user
    # * password
    # * use_ssl
    # * timeout
    def new3(hash={})

      # convert all keys into lowercase strings
      h = {}
      hash.each { |k,v| h[k.to_s.downcase] = v }

      self.new(h['host'], h['path'], h['port'], h['proxy_host'], h['proxy_port'], h['user'], h['password'],
               h['use_ssl'], h['timeout'])
    end

    alias new_from_hash new3

    end


    # Returns the Net::HTTP object for the client. If you want to
    # change HTTP client options except header, cookie, timeout,
    # user and password, use Net::HTTP directly.
    #
    # Since 2.1.0.
    attr_reader :http

    # Add additional HTTP headers to the request
    attr_accessor :http_header_extra

    # Returns the Net::HTTPResponse object of the last RPC.
    attr_reader :http_last_response

    # Get and set the HTTP Cookie header.
    attr_accessor :cookie


    # Return the corresponding attributes.
    attr_reader :timeout, :user, :password

    # Sets the Net::HTTP#read_timeout and Net::HTTP#open_timeout to
    # +new_timeout+
    def timeout=(new_timeout)
      @timeout = new_timeout
      @http.read_timeout = @timeout
      @http.open_timeout = @timeout
    end

    # Changes the user for the Basic Authentication header to +new_user+
    def user=(new_user)
      @user = new_user
      set_auth
    end

    # Changes the password for the Basic Authentication header to
    # +new_password+
    def password=(new_password)
      @password = new_password
      set_auth
    end

    # Invokes the method named +method+ with the parameters given by
    # +args+ on the XML-RPC server.
    #
    # The +method+ parameter is converted into a String and should
    # be a valid XML-RPC method-name.
    #
    # Each parameter of +args+ must be of one of the following types,
    # where Hash, Struct and Array can contain any of these listed _types_:
    #
    # * Integer
    # * TrueClass, FalseClass, +true+, +false+
    # * String, Symbol
    # * Float
    # * Hash, Struct
    # * Array
    # * Date, Time, XMLRPC::DateTime
    # * XMLRPC::Base64
    # * A Ruby object which class includes XMLRPC::Marshallable
    #   (only if Config::ENABLE_MARSHALLING is +true+).
    #   That object is converted into a hash, with one additional key/value
    #   pair <code>___class___</code> which contains the class name
    #   for restoring that object later.
    #
    # The method returns the return-value from the Remote Procedure Call.
    #
    # The type of the return-value is one of the types shown above.
    #
    # An Integer is only allowed when it fits in 32-bit. A XML-RPC
    # +dateTime.iso8601+ type is always returned as a XMLRPC::DateTime object.
    # Struct is never returned, only a Hash, the same for a Symbol, where as a
    # String is always returned. XMLRPC::Base64 is returned as a String from
    # xmlrpc4r version 1.6.1 on.
    #
    # If the remote procedure returned a fault-structure, then a
    # XMLRPC::FaultException exception is raised, which has two accessor-methods
    # +faultCode+ an Integer, and +faultString+ a String.
    def call(method, *args)
      ok, param = call2(method, *args)
      if ok
        param
      else
        raise param
      end
    end

    # The difference between this method and XMLRPC::Client#call is, that
    # this method will <b>NOT</b> raise a XMLRPC::FaultException exception.
    #
    # The method returns an array of two values. The first value indicates if
    # the second value is +true+ or an XMLRPC::FaultException.
    #
    # Both are explained in XMLRPC::Client#call.
    #
    # Simple to remember: The "2" in "call2" denotes the number of values it returns.
    def call2(method, *args)
      request = create().methodCall(method, *args)
      data = do_rpc(request, false)
      parser().parseMethodResponse(data)
    end

    # Similar to XMLRPC::Client#call, however can be called concurrently and
    # use a new connection for each request. In contrast to the corresponding
    # method without the +_async+ suffix, which use connect-alive (one
    # connection for all requests).
    #
    # Note, that you have to use Thread to call these methods concurrently.
    # The following example calls two methods concurrently:
    #
    #   Thread.new {
    #     p client.call_async("michael.add", 4, 5)
    #   }
    #
    #   Thread.new {
    #     p client.call_async("michael.div", 7, 9)
    #   }
    #
    def call_async(method, *args)
      ok, param = call2_async(method, *args)
      if ok
        param
      else
        raise param
      end
    end

    # Same as XMLRPC::Client#call2, but can be called concurrently.
    #
    # See also XMLRPC::Client#call_async
    def call2_async(method, *args)
      request = create().methodCall(method, *args)
      data = do_rpc(request, true)
      parser().parseMethodResponse(data)
    end


    # You can use this method to execute several methods on a XMLRPC server
    # which support the multi-call extension.
    #
    #     s.multicall(
    #       ['michael.add', 3, 4],
    #       ['michael.sub', 4, 5]
    #     )
    #     # => [7, -1]
    def multicall(*methods)
      ok, params = multicall2(*methods)
      if ok
        params
      else
        raise params
      end
    end

    # Same as XMLRPC::Client#multicall, but returns two parameters instead of
    # raising an XMLRPC::FaultException.
    #
    # See XMLRPC::Client#call2
    def multicall2(*methods)
      gen_multicall(methods, false)
    end

    # Similar to XMLRPC::Client#multicall, however can be called concurrently and
    # use a new connection for each request. In contrast to the corresponding
    # method without the +_async+ suffix, which use connect-alive (one
    # connection for all requests).
    #
    # Note, that you have to use Thread to call these methods concurrently.
    # The following example calls two methods concurrently:
    #
    #   Thread.new {
    #     p client.multicall_async("michael.add", 4, 5)
    #   }
    #
    #   Thread.new {
    #     p client.multicall_async("michael.div", 7, 9)
    #   }
    #
    def multicall_async(*methods)
      ok, params = multicall2_async(*methods)
      if ok
        params
      else
        raise params
      end
    end

    # Same as XMLRPC::Client#multicall2, but can be called concurrently.
    #
    # See also XMLRPC::Client#multicall_async
    def multicall2_async(*methods)
      gen_multicall(methods, true)
    end


    # Returns an object of class XMLRPC::Client::Proxy, initialized with
    # +prefix+ and +args+.
    #
    # A proxy object returned by this method behaves like XMLRPC::Client#call,
    # i.e. a call on that object will raise a XMLRPC::FaultException when a
    # fault-structure is returned by that call.
    def proxy(prefix=nil, *args)
      Proxy.new(self, prefix, args, :call)
    end

    # Almost the same like XMLRPC::Client#proxy only that a call on the returned
    # XMLRPC::Client::Proxy object will return two parameters.
    #
    # See XMLRPC::Client#call2
    def proxy2(prefix=nil, *args)
      Proxy.new(self, prefix, args, :call2)
    end

    # Similar to XMLRPC::Client#proxy, however can be called concurrently and
    # use a new connection for each request. In contrast to the corresponding
    # method without the +_async+ suffix, which use connect-alive (one
    # connection for all requests).
    #
    # Note, that you have to use Thread to call these methods concurrently.
    # The following example calls two methods concurrently:
    #
    #   Thread.new {
    #     p client.proxy_async("michael.add", 4, 5)
    #   }
    #
    #   Thread.new {
    #     p client.proxy_async("michael.div", 7, 9)
    #   }
    #
    def proxy_async(prefix=nil, *args)
      Proxy.new(self, prefix, args, :call_async)
    end

    # Same as XMLRPC::Client#proxy2, but can be called concurrently.
    #
    # See also XMLRPC::Client#proxy_async
    def proxy2_async(prefix=nil, *args)
      Proxy.new(self, prefix, args, :call2_async)
    end


    private

    def net_http(host, port, proxy_host, proxy_port)
      Net::HTTP.new host, port, proxy_host, proxy_port
    end

    def dup_net_http
      http = net_http(@http.address,
                      @http.port,
                      @http.proxy_address,
                      @http.proxy_port)
      http.proxy_user = @http.proxy_user
      http.proxy_pass = @http.proxy_pass
      if @http.use_ssl?
        http.use_ssl = true
        Net::HTTP::SSL_ATTRIBUTES.each do |attribute|
          http.__send__("#{attribute}=", @http.__send__(attribute))
        end
      end
      http.read_timeout = @http.read_timeout
      http.open_timeout = @http.open_timeout
      http
    end

    def set_auth
      if @user.nil?
        @auth = nil
      else
        a =  "#@user"
        a << ":#@password" if @password != nil
        @auth = "Basic " + [a].pack("m0")
      end
    end

    def do_rpc(request, async=false)
      header = {
       "User-Agent"     =>  USER_AGENT,
       "Content-Type"   => "text/xml; charset=utf-8",
       "Content-Length" => request.bytesize.to_s,
       "Connection"     => (async ? "close" : "keep-alive")
      }

      header["Cookie"] = @cookie        if @cookie
      header.update(@http_header_extra) if @http_header_extra

      if @auth != nil
        # add authorization header
        header["Authorization"] = @auth
      end

      resp = nil
      @http_last_response = nil

      if async
        # use a new HTTP object for each call
        http = dup_net_http

        # post request
        http.start {
          resp = http.request_post(@path, request, header)
        }
      else
        # reuse the HTTP object for each call => connection alive is possible
        # we must start connection explicitly first time so that http.request
        # does not assume that we don't want keepalive
        @http.start if not @http.started?

        # post request
        resp = @http.request_post(@path, request, header)
      end

      @http_last_response = resp

      data = resp.body

      if resp.code == "401"
        # Authorization Required
        raise "Authorization failed.\nHTTP-Error: #{resp.code} #{resp.message}"
      elsif resp.code[0,1] != "2"
        raise "HTTP-Error: #{resp.code} #{resp.message}"
      end

      # assume text/xml on instances where Content-Type header is not set
      ct_expected = resp["Content-Type"] || 'text/xml'
      ct = parse_content_type(ct_expected).first
      if ct != "text/xml"
        if ct == "text/html"
          raise "Wrong content-type (received '#{ct}' but expected 'text/xml'): \n#{data}"
        else
          raise "Wrong content-type (received '#{ct}' but expected 'text/xml')"
        end
      end

      expected = resp["Content-Length"] || "<unknown>"
      if data.nil? or data.bytesize == 0
        raise "Wrong size. Was #{data.bytesize}, should be #{expected}"
      end

      parse_set_cookies(resp.get_fields("Set-Cookie"))

      return data
    end

    def parse_set_cookies(set_cookies)
      return if set_cookies.nil?
      return if set_cookies.empty?
      require 'webrick/cookie'
      pairs = {}
      set_cookies.each do |set_cookie|
        cookie = WEBrick::Cookie.parse_set_cookie(set_cookie)
        pairs.delete(cookie.name)
        pairs[cookie.name] = cookie.value
      end
      cookies = pairs.collect do |name, value|
        WEBrick::Cookie.new(name, value).to_s
      end
      @cookie = cookies.join("; ")
    end

    def gen_multicall(methods=[], async=false)
      meth = :call2
      meth = :call2_async if async

      ok, params = self.send(meth, "system.multicall",
        methods.collect {|m| {'methodName' => m[0], 'params' => m[1..-1]} }
      )

      if ok
        params = params.collect do |param|
          if param.is_a? Array
            param[0]
          elsif param.is_a? Hash
            XMLRPC::FaultException.new(param["faultCode"], param["faultString"])
          else
            raise "Wrong multicall return value"
          end
        end
      end

      return ok, params
    end



    # XML-RPC calls look nicer!
    #
    # You can call any method onto objects of that class - the object handles
    # XMLRPC::Client::Proxy#method_missing and will forward the method call to
    # a XML-RPC server.
    #
    # Don't use this class directly, instead use the public instance method
    # XMLRPC::Client#proxy or XMLRPC::Client#proxy2.
    #
    #     require "xmlrpc/client"
    #
    #     server = XMLRPC::Client.new("www.ruby-lang.org", "/RPC2", 80)
    #
    #     michael  = server.proxy("michael")
    #     michael2 = server.proxy("michael", 4)
    #
    #     # both calls should return the same value '9'.
    #     p michael.add(4,5)
    #     p michael2.add(5)
    class Proxy

      # Creates an object which provides XMLRPC::Client::Proxy#method_missing.
      #
      # The given +server+ must be an instance of XMLRPC::Client, which is the
      # XML-RPC server to be used for a XML-RPC call.
      #
      # +prefix+ and +delim+ will be prepended to the method name called onto this object.
      #
      # An optional parameter +meth+ is the method to use for a RPC.
      # It can be either, call, call2, call_async, call2_async
      #
      # +args+ are arguments which are automatically given to every XML-RPC
      # call before being provided through +method_missing+.
      def initialize(server, prefix, args=[], meth=:call, delim=".")
        @server = server
        @prefix = prefix ? prefix + delim : ""
        @args   = args
        @meth   = meth
      end

      # Every method call is forwarded to the XML-RPC server defined in
      # XMLRPC::Client::Proxy#new.
      #
      # Note: Inherited methods from class Object cannot be used as XML-RPC
      # names, because they get around +method_missing+.
      def method_missing(mid, *args)
        pre = @prefix + mid.to_s
        arg = @args + args
        @server.send(@meth, pre, *arg)
      end

    end # class Proxy

  end # class Client

end # module XMLRPC
