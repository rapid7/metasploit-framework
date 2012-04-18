require "#{File.dirname(__FILE__)}/spec_setup"
require 'rack/cache/context'

describe 'Rack::Cache::Context' do
  before { setup_cache_context }
  after  { teardown_cache_context }

  it 'passes on non-GET/HEAD requests' do
    respond_with 200
    post '/'

    app.should.be.called
    response.should.be.ok
    cache.trace.should.include :pass
    response.headers.should.not.include 'Age'
  end

  it 'passes on rack-cache.force-pass' do
    respond_with 200
    get '/', {"rack-cache.force-pass" => true}

    app.should.be.called
    response.should.be.ok
    cache.trace.should == [:pass]
    response.headers.should.not.include 'Age'
  end

  %w[post put delete].each do |request_method|
    it "invalidates on #{request_method} requests" do
      respond_with 200
      request request_method, '/'

      app.should.be.called
      response.should.be.ok
      cache.trace.should.include :invalidate
      cache.trace.should.include :pass
    end
  end

  it 'does not cache with Authorization request header and non public response' do
    respond_with 200, 'ETag' => '"FOO"'
    get '/', 'HTTP_AUTHORIZATION' => 'basic foobarbaz'

    app.should.be.called
    response.should.be.ok
    response.headers['Cache-Control'].should.equal 'private'
    cache.trace.should.include :miss
    cache.trace.should.not.include :store
    response.headers.should.not.include 'Age'
  end

  it 'does cache with Authorization request header and public response' do
    respond_with 200, 'Cache-Control' => 'public', 'ETag' => '"FOO"'
    get '/', 'HTTP_AUTHORIZATION' => 'basic foobarbaz'

    app.should.be.called
    response.should.be.ok
    cache.trace.should.include :miss
    cache.trace.should.include :store
    cache.trace.should.not.include :ignore
    response.headers.should.include 'Age'
    response.headers['Cache-Control'].should.equal 'public'
  end

  it 'does not cache with Cookie header and non public response' do
    respond_with 200, 'ETag' => '"FOO"'
    get '/', 'HTTP_COOKIE' => 'foo=bar'

    app.should.be.called
    response.should.be.ok
    response.headers['Cache-Control'].should.equal 'private'
    cache.trace.should.include :miss
    cache.trace.should.not.include :store
    response.headers.should.not.include 'Age'
  end

  it 'does not cache requests with a Cookie header' do
    respond_with 200
    get '/', 'HTTP_COOKIE' => 'foo=bar'

    response.should.be.ok
    app.should.be.called
    cache.trace.should.include :miss
    cache.trace.should.not.include :store
    response.headers.should.not.include 'Age'
    response.headers['Cache-Control'].should.equal 'private'
  end

  it 'does remove Set-Cookie response header from a cacheable response' do
    respond_with 200, 'Cache-Control' => 'public', 'ETag' => '"FOO"', 'Set-Cookie' => 'TestCookie=OK'
    get '/'

    app.should.be.called
    response.should.be.ok
    cache.trace.should.include :store
    cache.trace.should.include :ignore
    response.headers['Set-Cookie'].should.be.nil
  end

  it 'does remove all configured ignore_headers from a cacheable response' do
    respond_with 200, 'Cache-Control' => 'public', 'ETag' => '"FOO"', 'SET-COOKIE' => 'TestCookie=OK', 'X-Strip-Me' => 'Secret'
    get '/', 'rack-cache.ignore_headers' => ['set-cookie', 'x-strip-me']

    app.should.be.called
    response.should.be.ok
    cache.trace.should.include :store
    cache.trace.should.include :ignore
    response.headers['Set-Cookie'].should.be.nil
    response.headers['x-strip-me'].should.be.nil
  end

  it 'does not remove Set-Cookie response header from a private response' do
    respond_with 200, 'Cache-Control' => 'private', 'Set-Cookie' => 'TestCookie=OK'
    get '/'

    app.should.be.called
    response.should.be.ok
    cache.trace.should.not.include :store
    cache.trace.should.not.include :ignore
    response.headers['Set-Cookie'].should.equal 'TestCookie=OK'
  end

  it 'responds with 304 when If-Modified-Since matches Last-Modified' do
    timestamp = Time.now.httpdate
    respond_with do |req,res|
      res.status = 200
      res['Last-Modified'] = timestamp
      res['Content-Type'] = 'text/plain'
      res.body = ['Hello World']
    end

    get '/',
      'HTTP_IF_MODIFIED_SINCE' => timestamp
    app.should.be.called
    response.status.should.equal 304
    response.original_headers.should.not.include 'Content-Length'
    response.original_headers.should.not.include 'Content-Type'
    response.body.should.empty
    cache.trace.should.include :miss
    cache.trace.should.include :store
  end

  it 'responds with 304 when If-None-Match matches ETag' do
    respond_with do |req,res|
      res.status = 200
      res['ETag'] = '12345'
      res['Content-Type'] = 'text/plain'
      res.body = ['Hello World']
    end

    get '/',
      'HTTP_IF_NONE_MATCH' => '12345'
    app.should.be.called
    response.status.should.equal 304
    response.original_headers.should.not.include 'Content-Length'
    response.original_headers.should.not.include 'Content-Type'
    response.headers.should.include 'ETag'
    response.body.should.empty
    cache.trace.should.include :miss
    cache.trace.should.include :store
  end

  it 'responds with 304 only if If-None-Match and If-Modified-Since both match' do
    timestamp = Time.now

    respond_with do |req,res|
      res.status = 200
      res['ETag'] = '12345'
      res['Last-Modified'] = timestamp.httpdate
      res['Content-Type'] = 'text/plain'
      res.body = ['Hello World']
    end

    # Only etag matches
    get '/',
      'HTTP_IF_NONE_MATCH' => '12345', 'HTTP_IF_MODIFIED_SINCE' => (timestamp - 1).httpdate
    app.should.be.called
    response.status.should.equal 200

    # Only last-modified matches
    get '/',
      'HTTP_IF_NONE_MATCH' => '1234', 'HTTP_IF_MODIFIED_SINCE' => timestamp.httpdate
    app.should.be.called
    response.status.should.equal 200

    # Both matches
    get '/',
      'HTTP_IF_NONE_MATCH' => '12345', 'HTTP_IF_MODIFIED_SINCE' => timestamp.httpdate
    app.should.be.called
    response.status.should.equal 304
  end

  it 'validates private responses cached on the client' do
    respond_with do |req,res|
      etags = req.env['HTTP_IF_NONE_MATCH'].to_s.split(/\s*,\s*/)
      if req.env['HTTP_COOKIE'] == 'authenticated'
        res['Cache-Control'] = 'private, no-store'
        res['ETag'] = '"private tag"'
        if etags.include?('"private tag"')
          res.status = 304
        else
          res.status = 200
          res['Content-Type'] = 'text/plain'
          res.body = ['private data']
        end
      else
        res['ETag'] = '"public tag"'
        if etags.include?('"public tag"')
          res.status = 304
        else
          res.status = 200
          res['Content-Type'] = 'text/plain'
          res.body = ['public data']
        end
      end
    end

    get '/'
    app.should.be.called
    response.status.should.equal 200
    response.headers['ETag'].should == '"public tag"'
    response.body.should == 'public data'
    cache.trace.should.include :miss
    cache.trace.should.include :store

    get '/', 'HTTP_COOKIE' => 'authenticated'
    app.should.be.called
    response.status.should.equal 200
    response.headers['ETag'].should == '"private tag"'
    response.body.should == 'private data'
    cache.trace.should.include :stale
    cache.trace.should.include :invalid
    cache.trace.should.not.include :store

    get '/',
      'HTTP_IF_NONE_MATCH' => '"public tag"'
    app.should.be.called
    response.status.should.equal 304
    response.headers['ETag'].should == '"public tag"'
    cache.trace.should.include :stale
    cache.trace.should.include :valid
    cache.trace.should.include :store

    get '/',
      'HTTP_IF_NONE_MATCH' => '"private tag"',
      'HTTP_COOKIE' => 'authenticated'
    app.should.be.called
    response.status.should.equal 304
    response.headers['ETag'].should == '"private tag"'
    cache.trace.should.include :valid
    cache.trace.should.not.include :store
  end

  it 'stores responses when no-cache request directive present' do
    respond_with 200, 'Expires' => (Time.now + 5).httpdate

    get '/', 'HTTP_CACHE_CONTROL' => 'no-cache'
    response.should.be.ok
    cache.trace.should.include :store
    response.headers.should.include 'Age'
  end

  it 'reloads responses when cache hits but no-cache request directive present ' +
     'when allow_reload is set true' do
    count = 0
    respond_with 200, 'Cache-Control' => 'max-age=10000' do |req,res|
      count+= 1
      res.body = (count == 1) ? ['Hello World'] : ['Goodbye World']
    end

    get '/'
    response.should.be.ok
    response.body.should.equal 'Hello World'
    cache.trace.should.include :store

    get '/'
    response.should.be.ok
    response.body.should.equal 'Hello World'
    cache.trace.should.include :fresh

    get '/',
      'rack-cache.allow_reload' => true,
      'HTTP_CACHE_CONTROL' => 'no-cache'
    response.should.be.ok
    response.body.should.equal 'Goodbye World'
    cache.trace.should.include :reload
    cache.trace.should.include :store
  end

  it 'does not reload responses when allow_reload is set false (default)' do
    count = 0
    respond_with 200, 'Cache-Control' => 'max-age=10000' do |req,res|
      count+= 1
      res.body = (count == 1) ? ['Hello World'] : ['Goodbye World']
    end

    get '/'
    response.should.be.ok
    response.body.should.equal 'Hello World'
    cache.trace.should.include :store

    get '/'
    response.should.be.ok
    response.body.should.equal 'Hello World'
    cache.trace.should.include :fresh

    get '/',
      'rack-cache.allow_reload' => false,
      'HTTP_CACHE_CONTROL' => 'no-cache'
    response.should.be.ok
    response.body.should.equal 'Hello World'
    cache.trace.should.not.include :reload

    # test again without explicitly setting the allow_reload option to false
    get '/',
      'HTTP_CACHE_CONTROL' => 'no-cache'
    response.should.be.ok
    response.body.should.equal 'Hello World'
    cache.trace.should.not.include :reload
  end

  it 'revalidates fresh cache entry when max-age request directive is exceeded ' +
     'when allow_revalidate option is set true' do
    count = 0
    respond_with do |req,res|
      count+= 1
      res['Cache-Control'] = 'max-age=10000'
      res['ETag'] = count.to_s
      res.body = (count == 1) ? ['Hello World'] : ['Goodbye World']
    end

    get '/'
    response.should.be.ok
    response.body.should.equal 'Hello World'
    cache.trace.should.include :store

    get '/'
    response.should.be.ok
    response.body.should.equal 'Hello World'
    cache.trace.should.include :fresh

    get '/',
      'rack-cache.allow_revalidate' => true,
      'HTTP_CACHE_CONTROL' => 'max-age=0'
    response.should.be.ok
    response.body.should.equal 'Goodbye World'
    cache.trace.should.include :stale
    cache.trace.should.include :invalid
    cache.trace.should.include :store
  end

  it 'does not revalidate fresh cache entry when enable_revalidate option is set false (default)' do
    count = 0
    respond_with do |req,res|
      count+= 1
      res['Cache-Control'] = 'max-age=10000'
      res['ETag'] = count.to_s
      res.body = (count == 1) ? ['Hello World'] : ['Goodbye World']
    end

    get '/'
    response.should.be.ok
    response.body.should.equal 'Hello World'
    cache.trace.should.include :store

    get '/'
    response.should.be.ok
    response.body.should.equal 'Hello World'
    cache.trace.should.include :fresh

    get '/',
      'rack-cache.allow_revalidate' => false,
      'HTTP_CACHE_CONTROL' => 'max-age=0'
    response.should.be.ok
    response.body.should.equal 'Hello World'
    cache.trace.should.not.include :stale
    cache.trace.should.not.include :invalid
    cache.trace.should.include :fresh

    # test again without explicitly setting the allow_revalidate option to false
    get '/',
      'HTTP_CACHE_CONTROL' => 'max-age=0'
    response.should.be.ok
    response.body.should.equal 'Hello World'
    cache.trace.should.not.include :stale
    cache.trace.should.not.include :invalid
    cache.trace.should.include :fresh
  end
  it 'fetches response from backend when cache misses' do
    respond_with 200, 'Expires' => (Time.now + 5).httpdate
    get '/'

    response.should.be.ok
    cache.trace.should.include :miss
    response.headers.should.include 'Age'
  end

  [(201..202),(204..206),(303..305),(400..403),(405..409),(411..417),(500..505)].each do |range|
    range.each do |response_code|
      it "does not cache #{response_code} responses" do
        respond_with response_code, 'Expires' => (Time.now + 5).httpdate
        get '/'

        cache.trace.should.not.include :store
        response.status.should.equal response_code
        response.headers.should.not.include 'Age'
      end
    end
  end

  it "does not cache responses with explicit no-store directive" do
    respond_with 200,
      'Expires' => (Time.now + 5).httpdate,
      'Cache-Control' => 'no-store'
    get '/'

    response.should.be.ok
    cache.trace.should.not.include :store
    response.headers.should.not.include 'Age'
  end

  it 'does not cache responses without freshness information or a validator' do
    respond_with 200
    get '/'

    response.should.be.ok
    cache.trace.should.not.include :store
  end

  it "caches responses with explicit no-cache directive" do
    respond_with 200,
      'Expires' => (Time.now + 5).httpdate,
      'Cache-Control' => 'no-cache'
    get '/'

    response.should.be.ok
    cache.trace.should.include :store
    response.headers.should.include 'Age'
  end

  it 'caches responses with an Expiration header' do
    respond_with 200, 'Expires' => (Time.now + 5).httpdate
    get '/'

    response.should.be.ok
    response.body.should.equal 'Hello World'
    response.headers.should.include 'Date'
    response['Age'].should.not.be.nil
    response['X-Content-Digest'].should.not.be.nil
    cache.trace.should.include :miss
    cache.trace.should.include :store
    cache.metastore.to_hash.keys.length.should.equal 1
  end

  it 'caches responses with a max-age directive' do
    respond_with 200, 'Cache-Control' => 'max-age=5'
    get '/'

    response.should.be.ok
    response.body.should.equal 'Hello World'
    response.headers.should.include 'Date'
    response['Age'].should.not.be.nil
    response['X-Content-Digest'].should.not.be.nil
    cache.trace.should.include :miss
    cache.trace.should.include :store
    cache.metastore.to_hash.keys.length.should.equal 1
  end

  it 'caches responses with a s-maxage directive' do
    respond_with 200, 'Cache-Control' => 's-maxage=5'
    get '/'

    response.should.be.ok
    response.body.should.equal 'Hello World'
    response.headers.should.include 'Date'
    response['Age'].should.not.be.nil
    response['X-Content-Digest'].should.not.be.nil
    cache.trace.should.include :miss
    cache.trace.should.include :store
    cache.metastore.to_hash.keys.length.should.equal 1
  end

  it 'caches responses with a Last-Modified validator but no freshness information' do
    respond_with 200, 'Last-Modified' => Time.now.httpdate
    get '/'

    response.should.be.ok
    response.body.should.equal 'Hello World'
    cache.trace.should.include :miss
    cache.trace.should.include :store
  end

  it 'caches responses with an ETag validator but no freshness information' do
    respond_with 200, 'ETag' => '"123456"'
    get '/'

    response.should.be.ok
    response.body.should.equal 'Hello World'
    cache.trace.should.include :miss
    cache.trace.should.include :store
  end

  it 'hits cached response with Expires header' do
    respond_with 200,
      'Date' => (Time.now - 5).httpdate,
      'Expires' => (Time.now + 5).httpdate

    get '/'
    app.should.be.called
    response.should.be.ok
    response.headers.should.include 'Date'
    cache.trace.should.include :miss
    cache.trace.should.include :store
    response.body.should.equal 'Hello World'

    get '/'
    response.should.be.ok
    app.should.not.be.called
    response['Date'].should.equal responses.first['Date']
    response['Age'].to_i.should.satisfy { |age| age > 0 }
    response['X-Content-Digest'].should.not.be.nil
    cache.trace.should.include :fresh
    cache.trace.should.not.include :store
    response.body.should.equal 'Hello World'
  end

  it 'hits cached response with max-age directive' do
    respond_with 200,
      'Date' => (Time.now - 5).httpdate,
      'Cache-Control' => 'max-age=10'

    get '/'
    app.should.be.called
    response.should.be.ok
    response.headers.should.include 'Date'
    cache.trace.should.include :miss
    cache.trace.should.include :store
    response.body.should.equal 'Hello World'

    get '/'
    response.should.be.ok
    app.should.not.be.called
    response['Date'].should.equal responses.first['Date']
    response['Age'].to_i.should.satisfy { |age| age > 0 }
    response['X-Content-Digest'].should.not.be.nil
    cache.trace.should.include :fresh
    cache.trace.should.not.include :store
    response.body.should.equal 'Hello World'
  end

  it 'hits cached response with s-maxage directive' do
    respond_with 200,
      'Date' => (Time.now - 5).httpdate,
      'Cache-Control' => 's-maxage=10, max-age=0'

    get '/'
    app.should.be.called
    response.should.be.ok
    response.headers.should.include 'Date'
    cache.trace.should.include :miss
    cache.trace.should.include :store
    response.body.should.equal 'Hello World'

    get '/'
    response.should.be.ok
    app.should.not.be.called
    response['Date'].should.equal responses.first['Date']
    response['Age'].to_i.should.satisfy { |age| age > 0 }
    response['X-Content-Digest'].should.not.be.nil
    cache.trace.should.include :fresh
    cache.trace.should.not.include :store
    response.body.should.equal 'Hello World'
  end

  it 'assigns default_ttl when response has no freshness information' do
    respond_with 200

    get '/', 'rack-cache.default_ttl' => 10
    app.should.be.called
    response.should.be.ok
    cache.trace.should.include :miss
    cache.trace.should.include :store
    response.body.should.equal 'Hello World'
    response['Cache-Control'].should.include 's-maxage=10'

    get '/', 'rack-cache.default_ttl' => 10
    response.should.be.ok
    app.should.not.be.called
    cache.trace.should.include :fresh
    cache.trace.should.not.include :store
    response.body.should.equal 'Hello World'
  end

  it 'does not assign default_ttl when response has must-revalidate directive' do
    respond_with 200,
      'Cache-Control' => 'must-revalidate'

    get '/', 'rack-cache.default_ttl' => 10
    app.should.be.called
    response.should.be.ok
    cache.trace.should.include :miss
    cache.trace.should.not.include :store
    response['Cache-Control'].should.not.include 's-maxage'
    response.body.should.equal 'Hello World'
  end

  it 'fetches full response when cache stale and no validators present' do
    respond_with 200, 'Expires' => (Time.now + 5).httpdate

    # build initial request
    get '/'
    app.should.be.called
    response.should.be.ok
    response.headers.should.include 'Date'
    response.headers.should.include 'X-Content-Digest'
    response.headers.should.include 'Age'
    cache.trace.should.include :miss
    cache.trace.should.include :store
    response.body.should.equal 'Hello World'

    # go in and play around with the cached metadata directly ...
    # XXX find some other way to do this
    hash = cache.metastore.to_hash
    hash.values.length.should.equal 1
    entries = Marshal.load(hash.values.first)
    entries.length.should.equal 1
    req, res = entries.first
    res['Expires'] = (Time.now - 1).httpdate
    hash[hash.keys.first] = Marshal.dump([[req, res]])

    # build subsequent request; should be found but miss due to freshness
    get '/'
    app.should.be.called
    response.should.be.ok
    response['Age'].to_i.should.equal 0
    response.headers.should.include 'X-Content-Digest'
    cache.trace.should.include :stale
    cache.trace.should.not.include :fresh
    cache.trace.should.not.include :miss
    cache.trace.should.include :store
    response.body.should.equal 'Hello World'
  end

  it 'validates cached responses with Last-Modified and no freshness information' do
    timestamp = Time.now.httpdate
    respond_with do |req,res|
      res['Last-Modified'] = timestamp
      if req.env['HTTP_IF_MODIFIED_SINCE'] == timestamp
        res.status = 304
        res.body = []
      end
    end

    # build initial request
    get '/'
    app.should.be.called
    response.should.be.ok
    response.headers.should.include 'Last-Modified'
    response.headers.should.include 'X-Content-Digest'
    response.body.should.equal 'Hello World'
    cache.trace.should.include :miss
    cache.trace.should.include :store
    cache.trace.should.not.include :stale

    # build subsequent request; should be found but miss due to freshness
    get '/'
    app.should.be.called
    response.should.be.ok
    response.headers.should.include 'Last-Modified'
    response.headers.should.include 'X-Content-Digest'
    response['Age'].to_i.should.equal 0
    response.body.should.equal 'Hello World'
    cache.trace.should.include :stale
    cache.trace.should.include :valid
    cache.trace.should.include :store
    cache.trace.should.not.include :miss
  end

  it 'validates cached responses with ETag and no freshness information' do
    timestamp = Time.now.httpdate
    respond_with do |req,res|
      res['ETAG'] = '"12345"'
      if req.env['HTTP_IF_NONE_MATCH'] == res['Etag']
        res.status = 304
        res.body = []
      end
    end

    # build initial request
    get '/'
    app.should.be.called
    response.should.be.ok
    response.headers.should.include 'ETag'
    response.headers.should.include 'X-Content-Digest'
    response.body.should.equal 'Hello World'
    cache.trace.should.include :miss
    cache.trace.should.include :store

    # build subsequent request; should be found but miss due to freshness
    get '/'
    app.should.be.called
    response.should.be.ok
    response.headers.should.include 'ETag'
    response.headers.should.include 'X-Content-Digest'
    response['Age'].to_i.should.equal 0
    response.body.should.equal 'Hello World'
    cache.trace.should.include :stale
    cache.trace.should.include :valid
    cache.trace.should.include :store
    cache.trace.should.not.include :miss
  end

  it 'replaces cached responses when validation results in non-304 response' do
    timestamp = Time.now.httpdate
    count = 0
    respond_with do |req,res|
      res['Last-Modified'] = timestamp
      case (count+=1)
      when 1 ; res.body = ['first response']
      when 2 ; res.body = ['second response']
      when 3
        res.body = []
        res.status = 304
      end
    end

    # first request should fetch from backend and store in cache
    get '/'
    response.status.should.equal 200
    response.body.should.equal 'first response'

    # second request is validated, is invalid, and replaces cached entry
    get '/'
    response.status.should.equal 200
    response.body.should.equal 'second response'

    # third respone is validated, valid, and returns cached entry
    get '/'
    response.status.should.equal 200
    response.body.should.equal 'second response'

    count.should.equal 3
  end

  it 'passes HEAD requests through directly on pass' do
    respond_with do |req,res|
      res.status = 200
      res.body = []
      req.request_method.should.equal 'HEAD'
    end

    head '/', 'HTTP_EXPECT' => 'something ...'
    app.should.be.called
    response.body.should.equal ''
  end

  it 'uses cache to respond to HEAD requests when fresh' do
    respond_with do |req,res|
      res['Cache-Control'] = 'max-age=10'
      res.body = ['Hello World']
      req.request_method.should.not.equal 'HEAD'
    end

    get '/'
    app.should.be.called
    response.status.should.equal 200
    response.body.should.equal 'Hello World'

    head '/'
    app.should.not.be.called
    response.status.should.equal 200
    response.body.should.equal ''
    response['Content-Length'].should.equal 'Hello World'.length.to_s
  end

  it 'invalidates cached responses on POST' do
    respond_with do |req,res|
      if req.request_method == 'GET'
        res.status = 200
        res['Cache-Control'] = 'public, max-age=500'
        res.body = ['Hello World']
      elsif req.request_method == 'POST'
        res.status = 303
        res['Location'] = '/'
        res.headers.delete('Cache-Control')
        res.body = []
      end
    end

    # build initial request to enter into the cache
    get '/'
    app.should.be.called
    response.should.be.ok
    response.body.should.equal 'Hello World'
    cache.trace.should.include :miss
    cache.trace.should.include :store

    # make sure it is valid
    get '/'
    app.should.not.called
    response.should.be.ok
    response.body.should.equal 'Hello World'
    cache.trace.should.include :fresh

    # now POST to same URL
    post '/'
    app.should.be.called
    response.should.be.redirect
    response['Location'].should.equal '/'
    cache.trace.should.include :invalidate
    cache.trace.should.include :pass
    response.body.should.equal ''

    # now make sure it was actually invalidated
    get '/'
    app.should.be.called
    response.should.be.ok
    response.body.should.equal 'Hello World'
    cache.trace.should.include :stale
    cache.trace.should.include :invalid
    cache.trace.should.include :store
  end

  describe 'with responses that include a Vary header' do
    before do
      count = 0
      respond_with 200 do |req,res|
        res['Vary'] = 'Accept User-Agent Foo'
        res['Cache-Control'] = 'max-age=10'
        res['X-Response-Count'] = (count+=1).to_s
        res.body = [req.env['HTTP_USER_AGENT']]
      end
    end

    it 'serves from cache when headers match' do
      get '/',
        'HTTP_ACCEPT' => 'text/html',
        'HTTP_USER_AGENT' => 'Bob/1.0'
      response.should.be.ok
      response.body.should.equal 'Bob/1.0'
      cache.trace.should.include :miss
      cache.trace.should.include :store

      get '/',
        'HTTP_ACCEPT' => 'text/html',
        'HTTP_USER_AGENT' => 'Bob/1.0'
      response.should.be.ok
      response.body.should.equal 'Bob/1.0'
      cache.trace.should.include :fresh
      cache.trace.should.not.include :store
      response.headers.should.include 'X-Content-Digest'
    end

    it 'stores multiple responses when headers differ' do
      get '/',
        'HTTP_ACCEPT' => 'text/html',
        'HTTP_USER_AGENT' => 'Bob/1.0'
      response.should.be.ok
      response.body.should.equal 'Bob/1.0'
      response['X-Response-Count'].should.equal '1'

      get '/',
        'HTTP_ACCEPT' => 'text/html',
        'HTTP_USER_AGENT' => 'Bob/2.0'
      cache.trace.should.include :miss
      cache.trace.should.include :store
      response.body.should.equal 'Bob/2.0'
      response['X-Response-Count'].should.equal '2'

      get '/',
        'HTTP_ACCEPT' => 'text/html',
        'HTTP_USER_AGENT' => 'Bob/1.0'
      cache.trace.should.include :fresh
      response.body.should.equal 'Bob/1.0'
      response['X-Response-Count'].should.equal '1'

      get '/',
        'HTTP_ACCEPT' => 'text/html',
        'HTTP_USER_AGENT' => 'Bob/2.0'
      cache.trace.should.include :fresh
      response.body.should.equal 'Bob/2.0'
      response['X-Response-Count'].should.equal '2'

      get '/',
        'HTTP_USER_AGENT' => 'Bob/2.0'
      cache.trace.should.include :miss
      response.body.should.equal 'Bob/2.0'
      response['X-Response-Count'].should.equal '3'
    end
  end

  it 'passes if there was a metastore exception' do
    respond_with 200, 'Cache-Control' => 'max-age=10000' do |req,res|
      res.body = ['Hello World']
    end

    get '/'
    response.should.be.ok
    response.body.should.equal 'Hello World'
    cache.trace.should.include :store

    get '/' do |cache|
      cache.meta_def(:metastore) { raise Timeout::Error }
    end
    response.should.be.ok
    response.body.should.equal 'Hello World'
    cache.trace.should.include :pass

    post '/' do |cache|
      cache.meta_def(:metastore) { raise Timeout::Error }
    end
    response.should.be.ok
    response.body.should.equal 'Hello World'
    cache.trace.should.include :pass
  end
end
