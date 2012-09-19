require 'rack/cache/options'
require 'rack/cache/request'
require 'rack/cache/response'
require 'rack/cache/storage'

module Rack::Cache
  # Implements Rack's middleware interface and provides the context for all
  # cache logic, including the core logic engine.
  class Context
    include Rack::Cache::Options

    # Array of trace Symbols
    attr_reader :trace

    # The Rack application object immediately downstream.
    attr_reader :backend

    def initialize(backend, options={})
      @backend = backend
      @trace = []
      @env = nil

      initialize_options options
      yield self if block_given?

      @private_header_keys =
        private_headers.map { |name| "HTTP_#{name.upcase.tr('-', '_')}" }
    end

    # The configured MetaStore instance. Changing the rack-cache.metastore
    # value effects the result of this method immediately.
    def metastore
      uri = options['rack-cache.metastore']
      storage.resolve_metastore_uri(uri)
    end

    # The configured EntityStore instance. Changing the rack-cache.entitystore
    # value effects the result of this method immediately.
    def entitystore
      uri = options['rack-cache.entitystore']
      storage.resolve_entitystore_uri(uri)
    end

    # The Rack call interface. The receiver acts as a prototype and runs
    # each request in a dup object unless the +rack.run_once+ variable is
    # set in the environment.
    def call(env)
      if env['rack.run_once']
        call! env
      else
        clone.call! env
      end
    end

    # The real Rack call interface. The caching logic is performed within
    # the context of the receiver.
    def call!(env)
      @trace = []
      @default_options.each { |k,v| env[k] ||= v }
      @env = env
      @request = Request.new(@env.dup.freeze)

      response =
        if @request.get? || @request.head?
          if !@env['HTTP_EXPECT'] && !@env['rack-cache.force-pass']
            lookup
          else
            pass
          end
        else
          invalidate
        end

      # log trace and set X-Rack-Cache tracing header
      trace = @trace.join(', ')
      response.headers['X-Rack-Cache'] = trace

      # write log message to rack.errors
      if verbose?
        message = "cache: [%s %s] %s\n" %
          [@request.request_method, @request.fullpath, trace]
        @env['rack.errors'].write(message)
      end

      # tidy up response a bit
      if (@request.get? || @request.head?) && not_modified?(response)
        response.not_modified!
      end

      if @request.head?
        response.body.close if response.body.respond_to?(:close)
        response.body = []
      end
      response.to_a
    end

  private

    # Record that an event took place.
    def record(event)
      @trace << event
    end

    # Does the request include authorization or other sensitive information
    # that should cause the response to be considered private by default?
    # Private responses are not stored in the cache.
    def private_request?
      @private_header_keys.any? { |key| @env.key?(key) }
    end

    # Determine if the #response validators (ETag, Last-Modified) matches
    # a conditional value specified in #request.
    def not_modified?(response)
      last_modified = @request.env['HTTP_IF_MODIFIED_SINCE']
      if etags = @request.env['HTTP_IF_NONE_MATCH']
        etags = etags.split(/\s*,\s*/)
        (etags.include?(response.etag) || etags.include?('*')) && (!last_modified || response.last_modified == last_modified)
      elsif last_modified
        response.last_modified == last_modified
      end
    end

    # Whether the cache entry is "fresh enough" to satisfy the request.
    def fresh_enough?(entry)
      if entry.fresh?
        if allow_revalidate? && max_age = @request.cache_control.max_age
          max_age > 0 && max_age >= entry.age
        else
          true
        end
      end
    end

    # Delegate the request to the backend and create the response.
    def forward
      Response.new(*backend.call(@env))
    end

    # The request is sent to the backend, and the backend's response is sent
    # to the client, but is not entered into the cache.
    def pass
      record :pass
      forward
    end

    # Invalidate POST, PUT, DELETE and all methods not understood by this cache
    # See RFC2616 13.10
    def invalidate
      metastore.invalidate(@request, entitystore)
    rescue Exception => e
      log_error(e)
      pass
    else
      record :invalidate
      pass
    end

    # Try to serve the response from cache. When a matching cache entry is
    # found and is fresh, use it as the response without forwarding any
    # request to the backend. When a matching cache entry is found but is
    # stale, attempt to #validate the entry with the backend using conditional
    # GET. When no matching cache entry is found, trigger #miss processing.
    def lookup
      if @request.no_cache? && allow_reload?
        record :reload
        fetch
      else
        begin
          entry = metastore.lookup(@request, entitystore)
        rescue Exception => e
          log_error(e)
          return pass
        end
        if entry
          if fresh_enough?(entry)
            record :fresh
            entry.headers['Age'] = entry.age.to_s
            entry
          else
            record :stale
            validate(entry)
          end
        else
          record :miss
          fetch
        end
      end
    end

    # Validate that the cache entry is fresh. The original request is used
    # as a template for a conditional GET request with the backend.
    def validate(entry)
      # send no head requests because we want content
      @env['REQUEST_METHOD'] = 'GET'

      # add our cached last-modified validator to the environment
      @env['HTTP_IF_MODIFIED_SINCE'] = entry.last_modified

      # Add our cached etag validator to the environment.
      # We keep the etags from the client to handle the case when the client
      # has a different private valid entry which is not cached here.
      cached_etags = entry.etag.to_s.split(/\s*,\s*/)
      request_etags = @request.env['HTTP_IF_NONE_MATCH'].to_s.split(/\s*,\s*/)
      etags = (cached_etags + request_etags).uniq
      @env['HTTP_IF_NONE_MATCH'] = etags.empty? ? nil : etags.join(', ')

      response = forward

      if response.status == 304
        record :valid

        # Check if the response validated which is not cached here
        etag = response.headers['ETag']
        return response if etag && request_etags.include?(etag) && !cached_etags.include?(etag)

        entry = entry.dup
        entry.headers.delete('Date')
        %w[Date Expires Cache-Control ETag Last-Modified].each do |name|
          next unless value = response.headers[name]
          entry.headers[name] = value
        end

        # even though it's empty, be sure to close the response body from upstream
        # because middleware use close to signal end of response
        response.body.close if response.body.respond_to?(:close)

        response = entry
      else
        record :invalid
      end

      store(response) if response.cacheable?

      response
    end

    # The cache missed or a reload is required. Forward the request to the
    # backend and determine whether the response should be stored. This allows
    # conditional / validation requests through to the backend but performs no
    # caching of the response when the backend returns a 304.
    def fetch
      # send no head requests because we want content
      @env['REQUEST_METHOD'] = 'GET'

      response = forward

      # Mark the response as explicitly private if any of the private
      # request headers are present and the response was not explicitly
      # declared public.
      if private_request? && !response.cache_control.public?
        response.private = true
      elsif default_ttl > 0 && response.ttl.nil? && !response.cache_control.must_revalidate?
        # assign a default TTL for the cache entry if none was specified in
        # the response; the must-revalidate cache control directive disables
        # default ttl assigment.
        response.ttl = default_ttl
      end

      store(response) if response.cacheable?

      response
    end

    # Write the response to the cache.
    def store(response)
      strip_ignore_headers(response)
      metastore.store(@request, response, entitystore)
      response.headers['Age'] = response.age.to_s
    rescue Exception => e
      log_error(e)
      nil
    else
      record :store
    end

    # Remove all ignored response headers before writing to the cache.
    def strip_ignore_headers(response)
      stripped_values = ignore_headers.map { |name| response.headers.delete(name) }
      record :ignore if stripped_values.any?
    end

    def log_error(exception)
      @env['rack.errors'].write("cache error: #{exception.message}\n#{exception.backtrace.join("\n")}\n")
    end
  end
end
