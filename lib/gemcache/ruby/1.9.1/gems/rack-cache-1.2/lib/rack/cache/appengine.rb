require 'base64'

module Rack::Cache::AppEngine

  module MC
    require 'java'

    import com.google.appengine.api.memcache.Expiration;
    import com.google.appengine.api.memcache.MemcacheService;
    import com.google.appengine.api.memcache.MemcacheServiceFactory;
    import com.google.appengine.api.memcache.Stats;

    Service = MemcacheServiceFactory.getMemcacheService
  end unless defined?(Rack::Cache::AppEngine::MC)

  class MemCache

      def initialize(options = {})
        @cache = MC::Service
        @cache.namespace = options[:namespace] if options[:namespace]
      end

      def contains?(key)
        MC::Service.contains(key)
      end

      def get(key)
        value = MC::Service.get(key)
        Marshal.load(Base64.decode64(value)) if value
      end

      def put(key, value, ttl = nil)
        expiration = ttl ? MC::Expiration.byDeltaSeconds(ttl) : nil
        value = Base64.encode64(Marshal.dump(value)).gsub(/\n/, '')
        MC::Service.put(key, value, expiration)
      end

      def namespace
        MC::Service.getNamespace
      end

      def namespace=(value)
        MC::Service.setNamespace(value.to_s)
      end

      def delete(key)
        MC::Service.delete(key)
      end

  end

end
