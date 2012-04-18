require 'sprockets/base'

module Sprockets
  # `Index` is a special cached version of `Environment`.
  #
  # The expection is that all of its file system methods are cached
  # for the instances lifetime. This makes `Index` much faster. This
  # behavior is ideal in production environments where the file system
  # is immutable.
  #
  # `Index` should not be initialized directly. Instead use
  # `Environment#index`.
  class Index < Base
    def initialize(environment)
      @environment = environment

      # Copy environment attributes
      @logger            = environment.logger
      @context_class     = environment.context_class
      @cache             = environment.cache
      @trail             = environment.trail.index
      @digest            = environment.digest
      @digest_class      = environment.digest_class
      @version           = environment.version
      @mime_types        = environment.mime_types
      @engines           = environment.engines
      @preprocessors     = environment.preprocessors
      @postprocessors    = environment.postprocessors
      @bundle_processors = environment.bundle_processors

      # Initialize caches
      @assets  = {}
      @digests = {}
    end

    # No-op return self as index
    def index
      self
    end

    # Cache calls to `file_digest`
    def file_digest(pathname)
      key = pathname.to_s
      if @digests.key?(key)
        @digests[key]
      else
        @digests[key] = super
      end
    end

    # Cache `find_asset` calls
    def find_asset(path, options = {})
      options[:bundle] = true unless options.key?(:bundle)
      if asset = @assets[cache_key_for(path, options)]
        asset
      elsif asset = super
        logical_path_cache_key = cache_key_for(path, options)
        full_path_cache_key    = cache_key_for(asset.pathname, options)

        # Cache on Index
        @assets[logical_path_cache_key] = @assets[full_path_cache_key] = asset

        # Push cache upstream to Environment
        @environment.instance_eval do
          @assets[logical_path_cache_key] = @assets[full_path_cache_key] = asset
        end

        asset
      end
    end

    protected
      # Index is immutable, any methods that try to clear the cache
      # should bomb.
      def expire_index!
        raise TypeError, "can't modify immutable index"
      end

      # Cache asset building in memory and in persisted cache.
      def build_asset(path, pathname, options)
        # Memory cache
        key = cache_key_for(pathname, options)
        if @assets.key?(key)
          @assets[key]
        else
          @assets[key] = begin
            # Persisted cache
            cache_asset(key) do
              super
            end
          end
        end
      end
  end
end
