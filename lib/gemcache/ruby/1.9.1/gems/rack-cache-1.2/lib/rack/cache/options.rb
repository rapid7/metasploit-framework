require 'rack/cache/key'
require 'rack/cache/storage'

module Rack::Cache

  # Configuration options and utility methods for option access. Rack::Cache
  # uses the Rack Environment to store option values. All options documented
  # below are stored in the Rack Environment as "rack-cache.<option>", where
  # <option> is the option name.
  module Options
    extend self

    def self.option_accessor(key)
      name = option_name(key)
      define_method(key) { || options[name] }
      define_method("#{key}=") { |value| options[name] = value }
      define_method("#{key}?") { || !! options[name] }
    end

    def option_name(key)
      case key
      when Symbol ; "rack-cache.#{key}"
      when String ; key
      else raise ArgumentError
      end
    end
    module_function :option_name

    # Enable verbose trace logging. This option is currently enabled by
    # default but is likely to be disabled in a future release.
    option_accessor :verbose

    # The storage resolver. Defaults to the Rack::Cache.storage singleton instance
    # of Rack::Cache::Storage. This object is responsible for resolving metastore
    # and entitystore URIs to an implementation instances.
    option_accessor :storage

    # A URI specifying the meta-store implementation that should be used to store
    # request/response meta information. The following URIs schemes are
    # supported:
    #
    # * heap:/
    # * file:/absolute/path or file:relative/path
    # * memcached://localhost:11211[/namespace]
    #
    # If no meta store is specified the 'heap:/' store is assumed. This
    # implementation has significant draw-backs so explicit configuration is
    # recommended.
    option_accessor :metastore

    # A custom cache key generator, which can be anything that responds to :call.
    # By default, this is the Rack::Cache::Key class, but you can implement your
    # own generator. A cache key generator gets passed a request and generates the
    # appropriate cache key.
    #
    # In addition to setting the generator to an object, you can just pass a block
    # instead, which will act as the cache key generator:
    #
    #   set :cache_key do |request|
    #     request.fullpath.replace(/\//, '-')
    #   end
    option_accessor :cache_key

    # A URI specifying the entity-store implementation that should be used to
    # store response bodies. See the metastore option for information on
    # supported URI schemes.
    #
    # If no entity store is specified the 'heap:/' store is assumed. This
    # implementation has significant draw-backs so explicit configuration is
    # recommended.
    option_accessor :entitystore

    # The number of seconds that a cache entry should be considered
    # "fresh" when no explicit freshness information is provided in
    # a response. Explicit Cache-Control or Expires headers
    # override this value.
    #
    # Default: 0
    option_accessor :default_ttl

    # Set of response headers that are removed before storing them in the
    # cache. These headers are only removed for cacheable responses.  For
    # example, in most cases, it makes sense to prevent cookies from being
    # stored in the cache.
    #
    # Default: ['Set-Cookie']
    option_accessor :ignore_headers

    # Set of request headers that trigger "private" cache-control behavior
    # on responses that don't explicitly state whether the response is
    # public or private via a Cache-Control directive. Applications that use
    # cookies for authorization may need to add the 'Cookie' header to this
    # list.
    #
    # Default: ['Authorization', 'Cookie']
    option_accessor :private_headers

    # Specifies whether the client can force a cache reload by including a
    # Cache-Control "no-cache" directive in the request. This is enabled by
    # default for compliance with RFC 2616.
    option_accessor :allow_reload

    # Specifies whether the client can force a cache revalidate by including
    # a Cache-Control "max-age=0" directive in the request. This is enabled by
    # default for compliance with RFC 2616.
    option_accessor :allow_revalidate

    # Specifies whether the underlying entity store's native expiration should
    # be used.
    option_accessor :use_native_ttl

    # The underlying options Hash. During initialization (or outside of a
    # request), this is a default values Hash. During a request, this is the
    # Rack environment Hash. The default values Hash is merged in underneath
    # the Rack environment before each request is processed.
    def options
      @env || @default_options
    end

    # Set multiple options.
    def options=(hash={})
      hash.each { |key,value| write_option(key, value) }
    end

    # Set an option. When +option+ is a Symbol, it is set in the Rack
    # Environment as "rack-cache.option". When +option+ is a String, it
    # exactly as specified. The +option+ argument may also be a Hash in
    # which case each key/value pair is merged into the environment as if
    # the #set method were called on each.
    def set(option, value=self, &block)
      if block_given?
        write_option option, block
      elsif value == self
        self.options = option.to_hash
      else
        write_option option, value
      end
    end

  private
    def initialize_options(options={})
      @default_options = {
        'rack-cache.cache_key'        => Key,
        'rack-cache.verbose'          => true,
        'rack-cache.storage'          => Rack::Cache::Storage.instance,
        'rack-cache.metastore'        => 'heap:/',
        'rack-cache.entitystore'      => 'heap:/',
        'rack-cache.default_ttl'      => 0,
        'rack-cache.ignore_headers'   => ['Set-Cookie'],
        'rack-cache.private_headers'  => ['Authorization', 'Cookie'],
        'rack-cache.allow_reload'     => false,
        'rack-cache.allow_revalidate' => false,
        'rack-cache.use_native_ttl'   => false,
      }
      self.options = options
    end

    def read_option(key)
      options[option_name(key)]
    end

    def write_option(key, value)
      options[option_name(key)] = value
    end
  end
end
