require 'pp'
require 'tmpdir'
require 'stringio'

[STDOUT, STDERR].each { |io| io.sync = true }

begin
  require 'bacon'
rescue LoadError => boom
  require 'rubygems' rescue nil
  require 'bacon'
end

# Set the MEMCACHED environment variable as follows to enable testing
# of the MemCached meta and entity stores.
ENV['MEMCACHED'] ||= 'localhost:11211'
$memcached = nil
$dalli = nil

def have_memcached?(server=ENV['MEMCACHED'])
  return $memcached unless $memcached.nil?

  # silence warnings from memcached
  begin
    v, $VERBOSE = $VERBOSE, nil
    require 'memcached'
  ensure
    $VERBOSE = v
  end

  $memcached = Memcached.new(server)
  $memcached.set('ping', '')
  true
rescue LoadError => boom
  warn "memcached library not available. related tests will be skipped."
  $memcached = false
  false
rescue => boom
  warn "memcached not working. related tests will be skipped."
  $memcached = false
  false
end

have_memcached?

def have_dalli?(server=ENV['MEMCACHED'])
  return $dalli unless $dalli.nil?
  require 'dalli'
  $dalli = Dalli::Client.new(server)
  $dalli.set('ping', '')
  true
rescue LoadError => boom
  warn "dalli library not available. related tests will be skipped."
  $dalli = false
  false
rescue => boom
  warn "dalli not working. related tests will be skipped."
  $dalli = false
  false
end

have_dalli?

def need_dalli(forwhat)
  yield if have_dalli?
end

def need_memcached(forwhat)
  yield if have_memcached?
end

def need_java(forwhat)
  yield if RUBY_PLATFORM =~ /java/
end


# Setup the load path ..
$LOAD_PATH.unshift File.dirname(File.dirname(__FILE__)) + '/lib'
$LOAD_PATH.unshift File.dirname(__FILE__)

require 'rack/cache'

# Methods for constructing downstream applications / response
# generators.
module CacheContextHelpers

  # The Rack::Cache::Context instance used for the most recent
  # request.
  attr_reader :cache

  # An Array of Rack::Cache::Context instances used for each request, in
  # request order.
  attr_reader :caches

  # The Rack::Response instance result of the most recent request.
  attr_reader :response

  # An Array of Rack::Response instances for each request, in request order.
  attr_reader :responses

  # The backend application object.
  attr_reader :app

  def setup_cache_context
    # holds each Rack::Cache::Context
    @app = nil

    # each time a request is made, a clone of @cache_template is used
    # and appended to @caches.
    @cache_template = nil
    @cache = nil
    @caches = []
    @errors = StringIO.new
    @cache_config = nil

    @called = false
    @request = nil
    @response = nil
    @responses = []

    @storage = Rack::Cache::Storage.new
  end

  def teardown_cache_context
    @app, @cache_template, @cache, @caches, @called,
    @request, @response, @responses, @cache_config, @cache_prototype = nil
  end

  # A basic response with 200 status code and a tiny body.
  def respond_with(status=200, headers={}, body=['Hello World'], &bk)
    called = false
    @app =
      lambda do |env|
        called = true
        response = Rack::Response.new(body, status, headers)
        request = Rack::Request.new(env)
        bk.call(request, response) if bk
        response.finish
      end
    @app.meta_def(:called?) { called }
    @app.meta_def(:reset!) { called = false }
    @app
  end

  def cache_config(&block)
    @cache_config = block
  end

  def request(method, uri='/', opts={})
    opts = {
      'rack.run_once' => true,
      'rack.errors' => @errors,
      'rack-cache.storage' => @storage
    }.merge(opts)

    fail 'response not specified (use respond_with)' if @app.nil?
    @app.reset! if @app.respond_to?(:reset!)

    @cache_prototype ||= Rack::Cache::Context.new(@app, &@cache_config)
    @cache = @cache_prototype.clone
    @caches << @cache
    @request = Rack::MockRequest.new(@cache)
    yield @cache if block_given?
    @response = @request.request(method.to_s.upcase, uri, opts)
    @responses << @response
    @response
  end

  def get(stem, env={}, &b)
    request(:get, stem, env, &b)
  end

  def head(stem, env={}, &b)
    request(:head, stem, env, &b)
  end

  def post(*args, &b)
    request(:post, *args, &b)
  end
end


module TestHelpers
  include FileUtils
  F = File

  @@temp_dir_count = 0

  def create_temp_directory
    @@temp_dir_count += 1
    path = F.join(Dir.tmpdir, "rack-cache-#{$$}-#{@@temp_dir_count}")
    mkdir_p path
    if block_given?
      yield path
      remove_entry_secure path
    end
    path
  end

  def create_temp_file(root, file, data='')
    path = F.join(root, file)
    mkdir_p F.dirname(path)
    F.open(path, 'w') { |io| io.write(data) }
  end

end

class Bacon::Context
  include TestHelpers
  include CacheContextHelpers
end

# Metaid == a few simple metaclass helper
# (See http://whytheluckystiff.net/articles/seeingMetaclassesClearly.html.)
class Object
  # The hidden singleton lurks behind everyone
  def metaclass; class << self; self; end; end
  def meta_eval(&blk); metaclass.instance_eval(&blk); end
  # Adds methods to a metaclass
  def meta_def name, &blk
    meta_eval { define_method name, &blk }
  end
  # Defines an instance method within a class
  def class_def name, &blk
    class_eval { define_method name, &blk }
  end

  # True when the Object is neither false or nil.
  def truthy?
    !!self
  end
end
