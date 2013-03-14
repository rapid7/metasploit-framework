require 'rack'

# = HTTP Caching For Rack
#
# Rack::Cache is suitable as a quick, drop-in component to enable HTTP caching
# for Rack-enabled applications that produce freshness (+Expires+, +Cache-Control+)
# and/or validation (+Last-Modified+, +ETag+) information.
#
# * Standards-based (RFC 2616 compliance)
# * Freshness/expiration based caching and validation
# * Supports HTTP Vary
# * Portable: 100% Ruby / works with any Rack-enabled framework
# * Disk, memcached, and heap memory storage backends
#
# === Usage
#
# Create with default options:
#   require 'rack/cache'
#   Rack::Cache.new(app, :verbose => true, :entitystore => 'file:cache')
#
# Within a rackup file (or with Rack::Builder):
#   require 'rack/cache'
#   use Rack::Cache do
#     set :verbose, true
#     set :metastore, 'memcached://localhost:11211/meta'
#     set :entitystore, 'file:/var/cache/rack'
#   end
#   run app
module Rack::Cache
  autoload :Request,      'rack/cache/request'
  autoload :Response,     'rack/cache/response'
  autoload :Context,      'rack/cache/context'
  autoload :Storage,      'rack/cache/storage'
  autoload :CacheControl, 'rack/cache/cachecontrol'

  # Create a new Rack::Cache middleware component that fetches resources from
  # the specified backend application. The +options+ Hash can be used to
  # specify default configuration values (see attributes defined in
  # Rack::Cache::Options for possible key/values). When a block is given, it
  # is executed within the context of the newly create Rack::Cache::Context
  # object.
  def self.new(backend, options={}, &b)
    Context.new(backend, options, &b)
  end
end
