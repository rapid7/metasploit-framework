module Sprockets
  # `Caching` is an internal mixin whose public methods are exposed on
  # the `Environment` and `Index` classes.
  module Caching
    protected
      # Cache helper method. Takes a `path` argument which maybe a
      # logical path or fully expanded path. The `&block` is passed
      # for finding and building the asset if its not in cache.
      def cache_asset(path)
        # If `cache` is not set, return fast
        if cache.nil?
          yield

        # Check cache for `path`
        elsif (asset = Asset.from_hash(self, cache_get_hash(path.to_s))) && asset.fresh?(self)
          asset

         # Otherwise yield block that slowly finds and builds the asset
        elsif asset = yield
          hash = {}
          asset.encode_with(hash)

          # Save the asset to its path
          cache_set_hash(path.to_s, hash)

          # Since path maybe a logical or full pathname, save the
          # asset its its full path too
          if path.to_s != asset.pathname.to_s
            cache_set_hash(asset.pathname.to_s, hash)
          end

          asset
        end
      end

    private
      # Strips `Environment#root` from key to make the key work
      # consisently across different servers. The key is also hashed
      # so it does not exceed 250 characters.
      def expand_cache_key(key)
        File.join('sprockets', digest_class.hexdigest(key.sub(root, '')))
      end

      def cache_get_hash(key)
        hash = cache_get(expand_cache_key(key))
        if hash.is_a?(Hash) && digest.hexdigest == hash['_version']
          hash
        end
      end

      def cache_set_hash(key, hash)
        hash['_version'] = digest.hexdigest
        cache_set(expand_cache_key(key), hash)
        hash
      end

      # Low level cache getter for `key`. Checks a number of supported
      # cache interfaces.
      def cache_get(key)
        # `Cache#get(key)` for Memcache
        if cache.respond_to?(:get)
          cache.get(key)

        # `Cache#[key]` so `Hash` can be used
        elsif cache.respond_to?(:[])
          cache[key]

        # `Cache#read(key)` for `ActiveSupport::Cache` support
        elsif cache.respond_to?(:read)
          cache.read(key)

        else
          nil
        end
      end

      # Low level cache setter for `key`. Checks a number of supported
      # cache interfaces.
      def cache_set(key, value)
        # `Cache#set(key, value)` for Memcache
        if cache.respond_to?(:set)
          cache.set(key, value)

        # `Cache#[key]=value` so `Hash` can be used
        elsif cache.respond_to?(:[]=)
          cache[key] = value

        # `Cache#write(key, value)` for `ActiveSupport::Cache` support
        elsif cache.respond_to?(:write)
          cache.write(key, value)
        end

        value
      end
  end
end
