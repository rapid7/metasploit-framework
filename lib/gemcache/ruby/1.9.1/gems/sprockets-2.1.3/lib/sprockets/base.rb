require 'sprockets/asset_attributes'
require 'sprockets/bundled_asset'
require 'sprockets/caching'
require 'sprockets/processed_asset'
require 'sprockets/processing'
require 'sprockets/server'
require 'sprockets/static_asset'
require 'sprockets/trail'
require 'pathname'

module Sprockets
  # `Base` class for `Environment` and `Index`.
  class Base
    include Caching, Processing, Server, Trail

    # Returns a `Digest` implementation class.
    #
    # Defaults to `Digest::MD5`.
    attr_reader :digest_class

    # Assign a `Digest` implementation class. This maybe any Ruby
    # `Digest::` implementation such as `Digest::MD5` or
    # `Digest::SHA1`.
    #
    #     environment.digest_class = Digest::SHA1
    #
    def digest_class=(klass)
      expire_index!
      @digest_class = klass
    end

    # The `Environment#version` is a custom value used for manually
    # expiring all asset caches.
    #
    # Sprockets is able to track most file and directory changes and
    # will take care of expiring the cache for you. However, its
    # impossible to know when any custom helpers change that you mix
    # into the `Context`.
    #
    # It would be wise to increment this value anytime you make a
    # configuration change to the `Environment` object.
    attr_reader :version

    # Assign an environment version.
    #
    #     environment.version = '2.0'
    #
    def version=(version)
      expire_index!
      @version = version
    end

    # Returns a `Digest` instance for the `Environment`.
    #
    # This value serves two purposes. If two `Environment`s have the
    # same digest value they can be treated as equal. This is more
    # useful for comparing environment states between processes rather
    # than in the same. Two equal `Environment`s can share the same
    # cached assets.
    #
    # The value also provides a seed digest for all `Asset`
    # digests. Any change in the environment digest will affect all of
    # its assets.
    def digest
      # Compute the initial digest using the implementation class. The
      # Sprockets release version and custom environment version are
      # mixed in. So any new releases will affect all your assets.
      @digest ||= digest_class.new.update(VERSION).update(version.to_s)

      # Returned a dupped copy so the caller can safely mutate it with `.update`
      @digest.dup
    end

    # Get and set `Logger` instance.
    attr_accessor :logger

    # Get `Context` class.
    #
    # This class maybe mutated and mixed in with custom helpers.
    #
    #     environment.context_class.instance_eval do
    #       include MyHelpers
    #       def asset_url; end
    #     end
    #
    attr_reader :context_class

    # Get persistent cache store
    attr_reader :cache

    # Set persistent cache store
    #
    # The cache store must implement a pair of getters and
    # setters. Either `get(key)`/`set(key, value)`,
    # `[key]`/`[key]=value`, `read(key)`/`write(key, value)`.
    def cache=(cache)
      expire_index!
      @cache = cache
    end

    # Return an `Index`. Must be implemented by the subclass.
    def index
      raise NotImplementedError
    end

    # Works like `Dir.entries`.
    #
    # Subclasses may cache this method.
    def entries(pathname)
      trail.entries(pathname)
    end

    # Works like `File.stat`.
    #
    # Subclasses may cache this method.
    def stat(path)
      trail.stat(path)
    end

    # Read and compute digest of filename.
    #
    # Subclasses may cache this method.
    def file_digest(path)
      if stat = self.stat(path)
        # If its a file, digest the contents
        if stat.file?
          digest.file(path.to_s)

        # If its a directive, digest the list of filenames
        elsif stat.directory?
          contents = self.entries(path).join(',')
          digest.update(contents)
        end
      end
    end

    # Internal. Return a `AssetAttributes` for `path`.
    def attributes_for(path)
      AssetAttributes.new(self, path)
    end

    # Internal. Return content type of `path`.
    def content_type_of(path)
      attributes_for(path).content_type
    end

    # Find asset by logical path or expanded path.
    def find_asset(path, options = {})
      logical_path = path
      pathname     = Pathname.new(path)

      if pathname.absolute?
        return unless stat(pathname)
        logical_path = attributes_for(pathname).logical_path
      else
        begin
          pathname = resolve(logical_path)
        rescue FileNotFound
          return nil
        end
      end

      build_asset(logical_path, pathname, options)
    end

    # Preferred `find_asset` shorthand.
    #
    #     environment['application.js']
    #
    def [](*args)
      find_asset(*args)
    end

    def each_entry(root, &block)
      return to_enum(__method__, root) unless block_given?
      root = Pathname.new(root) unless root.is_a?(Pathname)

      paths = []
      entries(root).sort.each do |filename|
        path = root.join(filename)
        paths << path

        if stat(path).directory?
          each_entry(path) do |subpath|
            paths << subpath
          end
        end
      end

      paths.sort_by(&:to_s).each(&block)

      nil
    end

    def each_file
      return to_enum(__method__) unless block_given?
      paths.each do |root|
        each_entry(root) do |path|
          if !stat(path).directory?
            yield path
          end
        end
      end
      nil
    end

    def each_logical_path
      return to_enum(__method__) unless block_given?
      files = {}
      each_file do |filename|
        logical_path = attributes_for(filename).logical_path
        yield logical_path unless files[logical_path]
        files[logical_path] = true
      end
      nil
    end

    # Pretty inspect
    def inspect
      "#<#{self.class}:0x#{object_id.to_s(16)} " +
        "root=#{root.to_s.inspect}, " +
        "paths=#{paths.inspect}, " +
        "digest=#{digest.to_s.inspect}" +
        ">"
    end

    protected
      # Clear index after mutating state. Must be implemented by the subclass.
      def expire_index!
        raise NotImplementedError
      end

      def build_asset(logical_path, pathname, options)
        pathname = Pathname.new(pathname)

        # If there are any processors to run on the pathname, use
        # `BundledAsset`. Otherwise use `StaticAsset` and treat is as binary.
        if attributes_for(pathname).processors.any?
          if options[:bundle] == false
            circular_call_protection(pathname.to_s) do
              ProcessedAsset.new(index, logical_path, pathname)
            end
          else
            BundledAsset.new(index, logical_path, pathname)
          end
        else
          StaticAsset.new(index, logical_path, pathname)
        end
      end

      def cache_key_for(path, options)
        "#{path}:#{options[:bundle] ? '1' : '0'}"
      end

      def circular_call_protection(path)
        reset = Thread.current[:sprockets_circular_calls].nil?
        calls = Thread.current[:sprockets_circular_calls] ||= Set.new
        if calls.include?(path)
          raise CircularDependencyError, "#{path} has already been required"
        end
        calls << path
        yield
      ensure
        Thread.current[:sprockets_circular_calls] = nil if reset
      end
  end
end
