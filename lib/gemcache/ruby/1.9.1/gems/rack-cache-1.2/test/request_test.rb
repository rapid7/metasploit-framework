require "#{File.dirname(__FILE__)}/spec_setup"
require 'rack/cache/request'

describe 'Rack::Cache::Request' do
  it 'is marked as no_cache when the Cache-Control header includes the no-cache directive' do
    request = Rack::Cache::Request.new('HTTP_CACHE_CONTROL' => 'public, no-cache')
    request.should.be.no_cache
  end

  it 'is marked as no_cache when request should not be loaded from cache' do
    request = Rack::Cache::Request.new('HTTP_PRAGMA' => 'no-cache')
    request.should.be.no_cache
  end

  it 'is not marked as no_cache when neither no-cache directive is specified' do
    request = Rack::Cache::Request.new('HTTP_CACHE_CONTROL' => 'public')
    request.should.not.be.no_cache
  end
end
