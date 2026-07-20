# -*- coding: binary -*-
##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# https://metasploit.com/framework/
##

require 'uri'

module Msf
class Auxiliary::Web::HTTP

  # Wraps a queued HTTP request and the callbacks that should process its response.
  class Request
    attr_accessor :url
    attr_reader	 :opts
    attr_reader	 :callbacks

    # @param url [String, URI] The target URL to request.
    # @param opts [Hash] Request options forwarded to {HTTP#request}.
    # @yield [response] Handles the completed response.
    # @yieldparam response [Response] The received response.
    def initialize( url, opts = {}, &callback )
      @url  = url.to_s.dup
      @opts = opts.dup

      @opts[:method] ||= :get

      @callbacks = [callback].compact
    end

    # @return [Symbol] The HTTP verb used when the request is executed.
    def method
      opts[:method]
    end
    
    # Calls each registered callback with the received response.
    #
    # @param response [Response] The response to dispatch.
    # @return [Array<Proc>] The stored callbacks.
    def handle_response( response )
      callbacks.each { |c| c.call response }
    end
  end

  # Decorates {Rex::Proto::Http::Response} with convenience helpers used by web auxiliaries.
  class Response < Rex::Proto::Http::Response

    # Builds a response object from a Rex HTTP response.
    #
    # @param response [Rex::Proto::Http::Response, nil] The response returned by Rex.
    # @return [Response] A wrapped response, or {empty} when no response was received.
    def self.from_rex_response( response )
      return empty if !response

      r = new( response.code, response.message, response.proto )
      response.instance_variables.each do |iv|
        r.instance_variable_set( iv, response.instance_variable_get( iv ) )
      end
      r
    end

    # @return [Response] An empty placeholder response.
    def self.empty
      new( 0, '' )
    end

    # Builds an empty response marked as having timed out.
    #
    # @return [Response] A timeout sentinel response.
    def self.timed_out
      r = empty
      r.timed_out
      r
    end

    # @return [Boolean] True when the request timed out.
    def timed_out?
      !!@timed_out
    end

    # Marks this response as timed out.
    #
    # @return [TrueClass] Always returns true.
    def timed_out
      @timed_out = true
    end
  end

  attr_reader :opts
  attr_reader :headers
  attr_reader :framework
  attr_reader :parent

  attr_accessor :redirect_limit
  attr_accessor :username , :password, :domain

  # @param opts [Hash] Configuration for the HTTP helper.
  # @option opts [Object] :framework The active framework instance used for threading.
  # @option opts [Object] :parent The owning module used for error reporting.
  # @option opts [Hash] :headers Additional HTTP headers to send with every request.
  # @option opts [String] :cookie_string Cookie header value to set by default.
  # @option opts [Hash] :auth Default authentication options.
  # @option opts [Integer] :redirect_limit Maximum redirects to follow.
  def initialize( opts = {} )
    @opts = opts.dup

    @framework = opts[:framework]
    @parent    = opts[:parent]

    @headers = {
      'Accept' => '*/*',
      'Cookie' => opts[:cookie_string]
    }.merge( opts[:headers] || {} )

    @headers.delete( 'Cookie' ) if !@headers['Cookie']

    @request_opts = {}
    if opts[:auth].is_a? Hash
      @username = opts[:auth][:user].to_s
      @password = opts[:auth][:password].to_s
      @domain   = opts[:auth][:domain].to_s
    end

    self.redirect_limit = opts[:redirect_limit] || 20

    @queue = Queue.new

    @after_run_blocks = []
  end

  # Registers a callback to be executed after {#run} drains the request queue.
  #
  # @yield A block to run after all queued requests finish.
  # @return [Array<Proc>] The accumulated after-run callbacks.
  def after_run( &block )
    @after_run_blocks << block
  end

  # Creates a Rex HTTP client using the configured target and authentication defaults.
  #
  # @return [Rex::Proto::Http::Client] A configured HTTP client.
  def connect
    c = Rex::Proto::Http::Client.new(
      opts[:target].host,
      opts[:target].port,
      {},
      opts[:target].ssl,
      'Auto',
      nil,
      username,
      password,
      subscriber: opts[:http_subscriber]
    )

    c.set_config({
      'vhost' => opts[:target].vhost,
      'ssl_server_name_indication' => opts[:target].ssl_server_name_indication || opts[:target].vhost,
      'agent' => opts[:user_agent] || Rex::UserAgent.session_agent,
      'domain' => domain
    })
    c
  end

  # Executes all queued asynchronous requests using the configured thread pool size.
  #
  # Callback exceptions are reported through the parent module and isolated from
  # the rest of the queue processing.
  #
  # @return [void]
  def run
    return if @queue.empty?

    tl = []
    loop do
      while tl.size <= (opts[:max_threads] || 5) && !@queue.empty? && (req = @queue.pop)
        tl << framework.threads.spawn( "#{self.class.name} - #{req})", false, req ) do |request|
          # Keep callback failures isolated.
          begin
            request.handle_response request( request.url, request.opts )
          rescue => e
            print_error e.to_s
            e.backtrace.each { |l| print_error l }
          end
        end
      end

      break if tl.empty?
      tl.reject! { |t| !t.alive? }

      select( nil, nil, nil, 0.05 )
    end

    call_after_run_blocks
  end

  # Sends an HTTP request and optionally follows redirect responses.
  #
  # @param url [String, URI] The URL to request.
  # @param opts [Hash] Request options forwarded to {#_request}.
  # @option opts [Boolean] :follow_redirect Whether to follow Location headers.
  # @return [Response, nil] The final response, or nil when the redirect limit is exceeded.
  def request( url, opts = {} )
    rlimit = self.redirect_limit

    while rlimit >= 0
      rlimit -= 1
      res = _request( url, opts )
      return res if !opts[:follow_redirect] || !url = res.headers['location']
    end
    nil
  end

  # Enqueues a request to be sent later by {#run}.
  #
  # @param url [String, URI] The URL to request.
  # @param opts [Hash] Request options.
  # @yield [response] Processes the response after execution.
  # @yieldparam response [Response] The completed response.
  # @return [Queue] The internal request queue.
  def request_async( url, opts = {}, &callback )
    queue Request.new( url, opts, &callback )
  end

  # Enqueues a GET request.
  #
  # @param url [String, URI] The URL to request.
  # @param opts [Hash] Additional request options.
  # @yield [response] Processes the response after execution.
  # @return [Queue] The internal request queue.
  def get_async( url, opts = {}, &callback )
    request_async( url, opts.merge( :method => :get ), &callback )
  end

  # Enqueues a POST request.
  #
  # @param url [String, URI] The URL to request.
  # @param opts [Hash] Additional request options.
  # @yield [response] Processes the response after execution.
  # @return [Queue] The internal request queue.
  def post_async( url, opts = {}, &callback )
    request_async( url, opts.merge( :method => :post ), &callback )
  end

  # Sends a synchronous GET request.
  #
  # @param url [String, URI] The URL to request.
  # @param opts [Hash] Additional request options.
  # @return [Response, nil] The received response.
  def get( url, opts = {} )
    request( url, opts.merge( :method => :get ) )
  end

  # Sends a synchronous POST request.
  #
  # @param url [String, URI] The URL to request.
  # @param opts [Hash] Additional request options.
  # @return [Response, nil] The received response.
  def post( url, opts = {} )
    request( url, opts.merge( :method => :post ) )
  end

  # Yields only when the supplied response body does not appear to be a custom 404 page.
  #
  # @param path [String] The original request path.
  # @param body [String] The response body to compare.
  # @yield Runs when the body is not identified as a custom 404.
  # @return [void]
  def if_not_custom_404( path, body, &callback )
    custom_404?( path, body ) { |b| callback.call if !b }
  end

  # Determines whether a response body matches the application's custom 404 behavior.
  #
  # The helper probes several random paths, refines their dynamic content, and compares
  # the result to the supplied response body.
  #
  # @param path [String] The original request path.
  # @param body [String] The response body to classify.
  # @yieldparam is_custom_404 [Boolean] True when the body matches the custom 404 fingerprint.
  # @return [nil] Returns nil immediately and reports the result via the callback.
  def custom_404?( path, body, &callback )
    return if !path || !body

    precision = 2

    trv_back = File.dirname( path )
    trv_back << '/' if trv_back[-1,1] != '/'

    # 404 probes
    generators = [
      # get a random path with an extension
      proc{ path + Rex::Text.rand_text_alpha( 10 ) + '.' + Rex::Text.rand_text_alpha( 10 )[0..precision] },

      # get a random path without an extension
      proc{ path + Rex::Text.rand_text_alpha( 10 ) },

      # move up a dir and get a random file
      proc{ trv_back + Rex::Text.rand_text_alpha( 10 ) },

      # move up a dir and get a random file with an extension
      proc{ trv_back + Rex::Text.rand_text_alpha( 10 ) + '.' + Rex::Text.rand_text_alpha( 10 )[0..precision] },

      # get a random directory
      proc{ path + Rex::Text.rand_text_alpha( 10 ) + '/' }
    ]

    synchronize do
      @@_404 ||= {}
      @@_404[path] ||= []

      @@_404_gathered ||= Set.new

      gathered = 0
      if !@@_404_gathered.include?( path.hash )
        generators.each.with_index do |generator, i|
          @@_404[path][i] ||= {}

          precision.times {
            get_async( generator.call, :follow_redirect => true ) do |res|
              gathered += 1

              if gathered == generators.size * precision
                @@_404_gathered << path.hash
                callback.call is_404?( path, body )
              else
                @@_404[path][i]['rdiff_now'] ||= false

                if !@@_404[path][i]['body']
                  @@_404[path][i]['body'] = res.body
                else
                  @@_404[path][i]['rdiff_now'] = true
                end

                if @@_404[path][i]['rdiff_now'] && !@@_404[path][i]['rdiff']
                  @@_404[path][i]['rdiff'] = Rex::Text.refine( @@_404[path][i]['body'], res.body )
                end
              end
            end
          }
        end
      else
        callback.call is_404?( path, body )
      end
    end

    nil
  end

  private

  # Runs and clears the callbacks registered through {#after_run}.
  #
  # @return [void]
  def call_after_run_blocks
    while block = @after_run_blocks.pop
      block.call
    end
  end

  # Executes a block while holding the helper's mutex.
  #
  # @yield The critical section.
  # @return [Object] The block result.
  def synchronize( &block )
    (@mutex ||= Mutex.new).synchronize( &block )
  end

  # Compares the supplied body to the cached custom 404 signatures for a path.
  #
  # @param path [String] The original request path.
  # @param body [String] The response body to compare.
  # @return [Boolean] True when the body matches the cached custom 404 fingerprint.
  def is_404?( path, body )
    @@_404[path].each { |_404| return true if Rex::Text.refine( _404['body'], body ) == _404['rdiff'] }
    false
  end

  # Appends a request to the internal work queue.
  #
  # @param request [Request] The queued request wrapper.
  # @return [Queue] The internal queue.
  def queue( request )
    @queue << request
  end

  # Issues a single HTTP request without following redirects.
  #
  # @param url [String, URI] The URL to request.
  # @param opts [Hash] Request options.
  # @option opts [String] :body Optional request body.
  # @option opts [Integer] :timeout Request timeout in seconds.
  # @option opts [Hash] :params Query string or POST parameters.
  # @option opts [Hash] :headers Per-request headers.
  # @option opts [Hash] :rex Direct Rex request overrides.
  # @return [Response] The response wrapper.
  def _request( url, opts = {} )
    body    = opts[:body]
    timeout = opts[:timeout] || 10
    method  = opts[:method].to_s.upcase || 'GET'
    url	    = url.is_a?( URI ) ? url : URI( url.to_s )

    rex_overrides = opts.delete( :rex ) || {}

    param_opts = {}

    if !(vars_get = Auxiliary::Web::Form.query_to_params( url.query )).empty?
      param_opts['vars_get'] = vars_get
    end

    if method == 'GET'
      param_opts['vars_get'] ||= {}
      param_opts['vars_get'].merge!( opts[:params] ) if opts[:params].is_a?( Hash )
    elsif method == 'POST'
      param_opts['vars_post'] = opts[:params] || {}
    end

    opts = @request_opts.merge( param_opts ).merge(
      'uri'     => url.path || '/',
      'method'  => method,
      'headers' => headers.merge( opts[:headers] || {} )
    # Allow for direct rex overrides
    ).merge( rex_overrides )

    opts['data'] = body if body

    c = connect
    if opts['username'] and opts['username'] != ''
      c.username = opts['username'].to_s
      c.password = opts['password'].to_s
    end
    Response.from_rex_response c.send_recv( c.request_cgi( opts ), timeout )
  rescue ::Timeout::Error
    Response.timed_out
  #rescue ::Errno::EPIPE, ::Errno::ECONNRESET, Rex::ConnectionTimeout
  # This is bad but we can't anticipate the gazilion different types of network
  # i/o errors between Rex and Errno.
  rescue => e
    elog e.to_s
    e.backtrace.each { |l| elog l }
    Response.empty
  end

  # Prints an error through the owning module when available.
  #
  # @param message [String] The message to report.
  # @return [void]
  def print_error( message )
    return if !@parent
    @parent.print_error message
  end

  alias_method :print_bad, :print_error

end
end
