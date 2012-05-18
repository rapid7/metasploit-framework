require 'fileutils'
require 'digest/sha1'
require 'rack/utils'
require 'rack/cache/key'

module Rack::Cache

  # The MetaStore is responsible for storing meta information about a
  # request/response pair keyed by the request's URL.
  #
  # The meta store keeps a list of request/response pairs for each canonical
  # request URL. A request/response pair is a two element Array of the form:
  #   [request, response]
  #
  # The +request+ element is a Hash of Rack environment keys. Only protocol
  # keys (i.e., those that start with "HTTP_") are stored. The +response+
  # element is a Hash of cached HTTP response headers for the paired request.
  #
  # The MetaStore class is abstract and should not be instanstiated
  # directly. Concrete subclasses should implement the protected #read,
  # #write, and #purge methods. Care has been taken to keep these low-level
  # methods dumb and straight-forward to implement.
  class MetaStore

    # Locate a cached response for the request provided. Returns a
    # Rack::Cache::Response object if the cache hits or nil if no cache entry
    # was found.
    def lookup(request, entity_store)
      key = cache_key(request)
      entries = read(key)

      # bail out if we have nothing cached
      return nil if entries.empty?

      # find a cached entry that matches the request.
      env = request.env
      match = entries.detect{|req,res| requests_match?(res['Vary'], env, req)}
      return nil if match.nil?

      _, res = match
      if body = entity_store.open(res['X-Content-Digest'])
        restore_response(res, body)
      else
        # TODO the metastore referenced an entity that doesn't exist in
        # the entitystore. we definitely want to return nil but we should
        # also purge the entry from the meta-store when this is detected.
      end
    end

    # Write a cache entry to the store under the given key. Existing
    # entries are read and any that match the response are removed.
    # This method calls #write with the new list of cache entries.
    def store(request, response, entity_store)
      key = cache_key(request)
      stored_env = persist_request(request)

      # write the response body to the entity store if this is the
      # original response.
      if response.headers['X-Content-Digest'].nil?
        if request.env['rack-cache.use_native_ttl'] && response.fresh?
          digest, size = entity_store.write(response.body, response.ttl)
        else
          digest, size = entity_store.write(response.body)
        end
        response.headers['X-Content-Digest'] = digest
        response.headers['Content-Length'] = size.to_s unless response.headers['Transfer-Encoding']
        response.body = entity_store.open(digest)
      end

      # read existing cache entries, remove non-varying, and add this one to
      # the list
      vary = response.vary
      entries =
        read(key).reject do |env,res|
          (vary == res['Vary']) &&
            requests_match?(vary, env, stored_env)
        end

      headers = persist_response(response)
      headers.delete 'Age'

      entries.unshift [stored_env, headers]
      write key, entries
      key
    end

    # Generate a cache key for the request.
    def cache_key(request)
      keygen = request.env['rack-cache.cache_key'] || Key
      keygen.call(request)
    end

    # Invalidate all cache entries that match the request.
    def invalidate(request, entity_store)
      modified = false
      key = cache_key(request)
      entries =
        read(key).map do |req, res|
          response = restore_response(res)
          if response.fresh?
            response.expire!
            modified = true
            [req, persist_response(response)]
          else
            [req, res]
          end
        end
      write key, entries if modified
    end

  private

    # Extract the environment Hash from +request+ while making any
    # necessary modifications in preparation for persistence. The Hash
    # returned must be marshalable.
    def persist_request(request)
      env = request.env.dup
      env.reject! { |key,val| key =~ /[^0-9A-Z_]/ || !val.respond_to?(:to_str) }
      env
    end

    # Converts a stored response hash into a Response object. The caller
    # is responsible for loading and passing the body if needed.
    def restore_response(hash, body=nil)
      status = hash.delete('X-Status').to_i
      Rack::Cache::Response.new(status, hash, body)
    end

    def persist_response(response)
      hash = response.headers.to_hash
      hash['X-Status'] = response.status.to_s
      hash
    end

    # Determine whether the two environment hashes are non-varying based on
    # the vary response header value provided.
    def requests_match?(vary, env1, env2)
      return true if vary.nil? || vary == ''
      vary.split(/[\s,]+/).all? do |header|
        key = "HTTP_#{header.upcase.tr('-', '_')}"
        env1[key] == env2[key]
      end
    end

  protected
    # Locate all cached request/response pairs that match the specified
    # URL key. The result must be an Array of all cached request/response
    # pairs. An empty Array must be returned if nothing is cached for
    # the specified key.
    def read(key)
      raise NotImplemented
    end

    # Store an Array of request/response pairs for the given key. Concrete
    # implementations should not attempt to filter or concatenate the
    # list in any way.
    def write(key, negotiations)
      raise NotImplemented
    end

    # Remove all cached entries at the key specified. No error is raised
    # when the key does not exist.
    def purge(key)
      raise NotImplemented
    end

  private
    # Generate a SHA1 hex digest for the specified string. This is a
    # simple utility method for meta store implementations.
    def hexdigest(data)
      Digest::SHA1.hexdigest(data)
    end

  public
    # Concrete MetaStore implementation that uses a simple Hash to store
    # request/response pairs on the heap.
    class Heap < MetaStore
      def initialize(hash={})
        @hash = hash
      end

      def read(key)
        if data = @hash[key]
          Marshal.load(data)
        else
          []
        end
      end

      def write(key, entries)
        @hash[key] = Marshal.dump(entries)
      end

      def purge(key)
        @hash.delete(key)
        nil
      end

      def to_hash
        @hash
      end

      def self.resolve(uri)
        new
      end
    end

    HEAP = Heap
    MEM = HEAP

    # Concrete MetaStore implementation that stores request/response
    # pairs on disk.
    class Disk < MetaStore
      attr_reader :root

      def initialize(root="/tmp/rack-cache/meta-#{ARGV[0]}")
        @root = File.expand_path(root)
        FileUtils.mkdir_p(root, :mode => 0755)
      end

      def read(key)
        path = key_path(key)
        File.open(path, 'rb') { |io| Marshal.load(io) }
      rescue Errno::ENOENT, IOError
        []
      end

      def write(key, entries)
        tries = 0
        begin
          path = key_path(key)
          File.open(path, 'wb') { |io| Marshal.dump(entries, io, -1) }
        rescue Errno::ENOENT, IOError
          Dir.mkdir(File.dirname(path), 0755)
          retry if (tries += 1) == 1
        end
      end

      def purge(key)
        path = key_path(key)
        File.unlink(path)
        nil
      rescue Errno::ENOENT, IOError
        nil
      end

    private
      def key_path(key)
        File.join(root, spread(hexdigest(key)))
      end

      def spread(sha, n=2)
        sha = sha.dup
        sha[n,0] = '/'
        sha
      end

    public
      def self.resolve(uri)
        path = File.expand_path(uri.opaque || uri.path)
        new path
      end

    end

    DISK = Disk
    FILE = Disk

    # Stores request/response pairs in memcached. Keys are not stored
    # directly since memcached has a 250-byte limit on key names. Instead,
    # the SHA1 hexdigest of the key is used.
    class MemCacheBase < MetaStore
      extend Rack::Utils

      # The MemCache object used to communicated with the memcached
      # daemon.
      attr_reader :cache

      # Create MemCache store for the given URI. The URI must specify
      # a host and may specify a port, namespace, and options:
      #
      # memcached://example.com:11211/namespace?opt1=val1&opt2=val2
      #
      # Query parameter names and values are documented with the memcached
      # library: http://tinyurl.com/4upqnd
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

          options[:namespace] = uri.path.to_s.sub(/^\//, '')

          new server, options
        else
          # if the object provided is not a URI, pass it straight through
          # to the underlying implementation.
          new uri
        end
      end
    end

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

      def read(key)
        key = hexdigest(key)
        cache.get(key) || []
      end

      def write(key, entries)
        key = hexdigest(key)
        cache.set(key, entries)
      end

      def purge(key)
        cache.delete(hexdigest(key))
        nil
      end
    end

    class MemCached < MemCacheBase
      # The Memcached instance used to communicated with the memcached
      # daemon.
      attr_reader :cache

      def initialize(server="localhost:11211", options={})
        options[:prefix_key] ||= options.delete(:namespace) if options.key?(:namespace)
        @cache =
          if server.respond_to?(:stats)
            server
          else
            require 'memcached'
            Memcached.new(server, options)
          end
      end

      def read(key)
        key = hexdigest(key)
        cache.get(key)
      rescue Memcached::NotFound
        []
      end

      def write(key, entries)
        key = hexdigest(key)
        cache.set(key, entries)
      end

      def purge(key)
        key = hexdigest(key)
        cache.delete(key)
        nil
      rescue Memcached::NotFound
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

    class GAEStore < MetaStore
      attr_reader :cache

      def initialize(options = {})
        require 'rack/cache/appengine'
        @cache = Rack::Cache::AppEngine::MemCache.new(options)
      end

      def read(key)
        key = hexdigest(key)
        cache.get(key) || []
      end

      def write(key, entries)
        key = hexdigest(key)
        cache.put(key, entries)
      end

      def purge(key)
        key = hexdigest(key)
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
