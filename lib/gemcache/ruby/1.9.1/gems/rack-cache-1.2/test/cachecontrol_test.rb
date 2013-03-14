require "#{File.dirname(__FILE__)}/spec_setup"
require 'rack/cache/cachecontrol'

describe 'Rack::Cache::CacheControl' do
  it 'takes no args and initializes with an empty set of values' do
    cache_control = Rack::Cache::CacheControl.new
    cache_control.should.be.empty
    cache_control.to_s.should.equal ''
  end

  it 'takes a String and parses it into a Hash when created' do
    cache_control = Rack::Cache::CacheControl.new('max-age=600, foo')
    cache_control['max-age'].should.equal '600'
    cache_control['foo'].should.be.true
  end

  it 'takes a String with a single name=value pair' do
    cache_control = Rack::Cache::CacheControl.new('max-age=600')
    cache_control['max-age'].should.equal '600'
  end

  it 'takes a String with multiple name=value pairs' do
    cache_control = Rack::Cache::CacheControl.new('max-age=600, max-stale=300, min-fresh=570')
    cache_control['max-age'].should.equal '600'
    cache_control['max-stale'].should.equal '300'
    cache_control['min-fresh'].should.equal '570'
  end

  it 'takes a String with a single flag value' do
    cache_control = Rack::Cache::CacheControl.new('no-cache')
    cache_control.should.include 'no-cache'
    cache_control['no-cache'].should.be.true
  end

  it 'takes a String with a bunch of all kinds of stuff' do
    cache_control =
      Rack::Cache::CacheControl.new('max-age=600,must-revalidate,min-fresh=3000,foo=bar,baz')
    cache_control['max-age'].should.equal '600'
    cache_control['must-revalidate'].should.be.true
    cache_control['min-fresh'].should.equal '3000'
    cache_control['foo'].should.equal 'bar'
    cache_control['baz'].should.be.true
  end

  it 'strips leading and trailing spaces from header value' do
    cache_control = Rack::Cache::CacheControl.new('   public,   max-age =   600  ')
    cache_control.should.include 'public'
    cache_control.should.include 'max-age'
    cache_control['max-age'].should.equal '600'
  end

  it 'strips blank segments' do
    cache_control = Rack::Cache::CacheControl.new('max-age=600,,max-stale=300')
    cache_control['max-age'].should.equal '600'
    cache_control['max-stale'].should.equal '300'
  end

  it 'removes all directives with #clear' do
    cache_control = Rack::Cache::CacheControl.new('max-age=600, must-revalidate')
    cache_control.clear
    cache_control.should.be.empty
  end

  it 'converts self into header String with #to_s' do
    cache_control = Rack::Cache::CacheControl.new
    cache_control['public'] = true
    cache_control['max-age'] = '600'
    cache_control.to_s.split(', ').sort.should.equal ['max-age=600', 'public']
  end

  it 'sorts alphabetically with boolean directives before value directives' do
    cache_control = Rack::Cache::CacheControl.new('foo=bar, z, x, y, bling=baz, zoom=zib, b, a')
    cache_control.to_s.should.equal 'a, b, x, y, z, bling=baz, foo=bar, zoom=zib'
  end

  it 'responds to #max_age with an integer when max-age directive present' do
    cache_control = Rack::Cache::CacheControl.new('public, max-age=600')
    cache_control.max_age.should.equal 600
  end

  it 'responds to #max_age with nil when no max-age directive present' do
    cache_control = Rack::Cache::CacheControl.new('public')
    cache_control.max_age.should.be.nil
  end

  it 'responds to #shared_max_age with an integer when s-maxage directive present' do
    cache_control = Rack::Cache::CacheControl.new('public, s-maxage=600')
    cache_control.shared_max_age.should.equal 600
  end

  it 'responds to #shared_max_age with nil when no s-maxage directive present' do
    cache_control = Rack::Cache::CacheControl.new('public')
    cache_control.shared_max_age.should.be.nil
  end

  it 'responds to #public? truthfully when public directive present' do
    cache_control = Rack::Cache::CacheControl.new('public')
    cache_control.should.be.public
  end

  it 'responds to #public? non-truthfully when no public directive present' do
    cache_control = Rack::Cache::CacheControl.new('private')
    cache_control.should.not.be.public
  end

  it 'responds to #private? truthfully when private directive present' do
    cache_control = Rack::Cache::CacheControl.new('private')
    cache_control.should.be.private
  end

  it 'responds to #private? non-truthfully when no private directive present' do
    cache_control = Rack::Cache::CacheControl.new('public')
    cache_control.should.not.be.private
  end

  it 'responds to #no_cache? truthfully when no-cache directive present' do
    cache_control = Rack::Cache::CacheControl.new('no-cache')
    cache_control.should.be.no_cache
  end

  it 'responds to #no_cache? non-truthfully when no no-cache directive present' do
    cache_control = Rack::Cache::CacheControl.new('max-age=600')
    cache_control.should.not.be.no_cache
  end

  it 'responds to #must_revalidate? truthfully when must-revalidate directive present' do
    cache_control = Rack::Cache::CacheControl.new('must-revalidate')
    cache_control.should.be.must_revalidate
  end

  it 'responds to #must_revalidate? non-truthfully when no must-revalidate directive present' do
    cache_control = Rack::Cache::CacheControl.new('max-age=600')
    cache_control.should.not.be.no_cache
  end

  it 'responds to #proxy_revalidate? truthfully when proxy-revalidate directive present' do
    cache_control = Rack::Cache::CacheControl.new('proxy-revalidate')
    cache_control.should.be.proxy_revalidate
  end

  it 'responds to #proxy_revalidate? non-truthfully when no proxy-revalidate directive present' do
    cache_control = Rack::Cache::CacheControl.new('max-age=600')
    cache_control.should.not.be.no_cache
  end
end
