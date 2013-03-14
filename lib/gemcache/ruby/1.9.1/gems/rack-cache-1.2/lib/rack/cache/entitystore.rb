require 'digest/sha1'

module Rack::Cache

  # Entity stores are used to cache response bodies across requests. All
  # Implementations are required to calculate a SHA checksum of the data written
  # which becomes the response body's key.
  class EntityStore

    # Read body calculating the SHA1 checksum and size while
    # yielding each chunk to the block. If the body responds to close,
    # call it after iteration is complete. Return a two-tuple of the form:
    # [ hexdigest, size ].
    def slurp(body)
      digest, size = Digest::SHA1.new, 0
      body.each do |part|
        size += bytesize(part)
        digest << part
        yield part
      end
      body.close if body.respond_to? :close
      [digest.hexdigest, size]
    end

    if ''.respond_to?(:bytesize)
      def bytesize(string); string.bytesize; end
    else
      def bytesize(string); string.size; end
    end

    private :slurp, :bytesize


    # Stores entity bodies on the heap using a Hash object.
    class Heap < EntityStore

      # Create the store with the specified backing Hash.
      def initialize(hash={})
        @hash = hash
      end

      # Determine whether the response body with the specified key (SHA1)
      # exists in the store.
      def exist?(key)
        @hash.include?(key)
      end

      # Return an object suitable for use as a Rack response body for the
      # specified key.
      def open(key)
        (body = @hash[key]) && body.dup
      end

      # Read all data associated with the given key and return as a single
      # String.
      def read(key)
        (body = @hash[key]) && body.join
      end

      # Write the Rack response body immediately and return the SHA1 key.
      def write(body, ttl=nil)
        buf = []
        key, size = slurp(body) { |part| buf << part }
        @hash[key] = buf
        [key, size]
      end

      # Remove the body corresponding to key; return nil.
      def purge(key)
        @hash.delete(key)
        nil
      end

      def self.resolve(uri)
        new
      end
    end

    HEAP = Heap
    MEM  = Heap

    # Stores entity bodies on disk at the specified path.
    class Disk < EntityStore

      # Path where entities should be stored. This directory is
      # created the first time the store is instansiated if it does not
      # already exist.
      attr_reader :root

      def initialize(root)
        @root = root
        FileUtils.mkdir_p root, :mode => 0755
      end

      def exist?(key)
        File.exist?(body_path(key))
      end

      def read(key)
        File.open(body_path(key), 'rb') { |f| f.read }
      rescue Errno::ENOENT
        nil
      end

      class Body < ::File #:nodoc:
        def each
          while part = read(8192)
            yield part
          end
        end
        alias_method :to_path, :path
      end

      # Open the entity body and return an IO object. The IO object's
      # each method is overridden to read 8K chunks instead of lines.
      def open(key)
        Body.open(body_path(key), 'rb')
      rescue Errno::ENOENT
        nil
      end

      def write(body, ttl=nil)
        filename = ['buf', $$, Thread.current.object_id].join('-')
        temp_file = storage_path(filename)
        key, size =
          File.open(temp_file, 'wb') { |dest|
            slurp(body) { |part| dest.write(part) }
          }

        path = body_path(key)
        if File.exist?(path)
          File.unlink temp_file
        else
          FileUtils.mkdir_p File.dirname(path), :mode => 0755
          FileUtils.mv temp_file, path
        end
        [key, size]
      end

      def purge(key)
        File.unlink body_path(key)
        nil
      rescue Errno::ENOENT
        nil
      end

    protected
      def storage_path(stem)
        File.join root, stem
      end

      def spread(key)
        key = key.dup
        key[2,0] = '/'
        key
      end

      def body_path(key)
        storage_path spread(key)
      end

      def self.resolve(uri)
        path = File.expand_path(uri.opaque || uri.path)
        new path
      end
    end

    DISK = Disk
    FILE = Disk

    # Base class for memcached entity stores.
    class MemCacheBase < EntityStore
      # The underlying Memcached instance used to communicate with the
      # memcached daemon.
      attr_reader :cache

      extend Rack::Utils

      def open(key)
        data = read(key)
        data && [data]
      end

      def self.resolve(uri)
        if uri.respond_to?(:scheme)
          server = "#{uri.host}:#{uri.port || '11211'}"
          options = parse_query(uri.query)
          options.keys.each do |key|
            value =
              case value = options.delete(key)
              when 'true' ; true
              when 'false' ; false
              else value.to_sym
              end
            options[key.to_sym] = value
          end
          options[:namespace] = uri.path.sub(/^\//, '')
          new server, options
        else
          # if the object provided is not a URI, pass it straight through
          # to the underlying implementation.
          new uri
        end
      end
    end

    # Uses the Dalli ruby library. This is the default unless
    # the memcached library has already been required.
    class Dalli < MemCacheBase
      def initialize(server="localhost:11211", options={})
        @cache =
          if server.respond_to?(:stats)
            server
          else
            require 'dalli'
            ::Dalli::Client.new(server, options)
          end
      end

      def exist?(key)
        !cache.get(key).nil?
      end

      def read(key)
        data = cache.get(key)
        data.force_encoding('BINARY') if data.respond_to?(:force_encoding)
        data
      end

      def write(body, ttl=nil)
        buf = StringIO.new
        key, size = slurp(body){|part| buf.write(part) }
        [key, size] if cache.set(key, buf.string, ttl)
      end

      def purge(key)
        cache.delete(key)
        nil
      end
    end

    # Uses the memcached client library. The ruby based memcache-client is used
    # in preference to this store unless the memcached library has already been
    # required.
    class MemCached < MemCacheBase
      def initialize(server="localhost:11211", options={})
        options[:prefix_key] ||= options.delete(:namespace) if options.key?(:namespace)
        @cache =
          if server.respond_to?(:stats)
            server
          else
            require 'memcached'
            ::Memcached.new(server, options)
          end
      end

      def exist?(key)
        cache.append(key, '')
        true
      rescue ::Memcached::NotStored
        false
      end

      def read(key)
        cache.get(key, false)
      rescue ::Memcached::NotFound
        nil
      end

      def write(body, ttl=0)
        buf = StringIO.new
        key, size = slurp(body){|part| buf.write(part) }
        cache.set(key, buf.string, ttl, false)
        [key, size]
      end

      def purge(key)
        cache.delete(key)
        nil
      rescue ::Memcached::NotFound
        nil
      end
    end

    MEMCACHE =
      if defined?(::Memcached)
        MemCached
      else
        Dalli
      end

    MEMCACHED = MEMCACHE

    class GAEStore < EntityStore
      attr_reader :cache

      def initialize(options = {})
        require 'rack/cache/appengine'
        @cache = Rack::Cache::AppEngine::MemCache.new(options)
      end

      def exist?(key)
        cache.contains?(key)
      end

      def read(key)
        cache.get(key)
      end

      def open(key)
        if data = read(key)
          [data]
        else
          nil
        end
      end

      def write(body, ttl=nil)
        buf = StringIO.new
        key, size = slurp(body){|part| buf.write(part) }
        cache.put(key, buf.string, ttl)
        [key, size]
      end

      def purge(key)
        cache.delete(key)
        nil
      end

      def self.resolve(uri)
        self.new(:namespace => uri.host)
      end

    end

    GAECACHE = GAEStore
    GAE = GAEStore

  end

end
