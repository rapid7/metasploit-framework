require 'time'
require 'rack/conditionalget'
require 'rack/mock'

describe Rack::ConditionalGet do
  def conditional_get(app)
    Rack::Lint.new Rack::ConditionalGet.new(app)
  end
  
  should "set a 304 status and truncate body when If-Modified-Since hits" do
    timestamp = Time.now.httpdate
    app = conditional_get(lambda { |env|
      [200, {'Last-Modified'=>timestamp}, ['TEST']] })

    response = Rack::MockRequest.new(app).
      get("/", 'HTTP_IF_MODIFIED_SINCE' => timestamp)

    response.status.should.equal 304
    response.body.should.be.empty
  end

  should "set a 304 status and truncate body when If-Modified-Since hits and is higher than current time" do
    app = conditional_get(lambda { |env|
      [200, {'Last-Modified'=>(Time.now - 3600).httpdate}, ['TEST']] })

    response = Rack::MockRequest.new(app).
      get("/", 'HTTP_IF_MODIFIED_SINCE' => Time.now.httpdate)

    response.status.should.equal 304
    response.body.should.be.empty
  end

  should "set a 304 status and truncate body when If-None-Match hits" do
    app = conditional_get(lambda { |env|
      [200, {'Etag'=>'1234'}, ['TEST']] })

    response = Rack::MockRequest.new(app).
      get("/", 'HTTP_IF_NONE_MATCH' => '1234')

    response.status.should.equal 304
    response.body.should.be.empty
  end

  should "not set a 304 status if If-Modified-Since hits but Etag does not" do
    timestamp = Time.now.httpdate
    app = conditional_get(lambda { |env|
      [200, {'Last-Modified'=>timestamp, 'Etag'=>'1234', 'Content-Type' => 'text/plain'}, ['TEST']] })

    response = Rack::MockRequest.new(app).
      get("/", 'HTTP_IF_MODIFIED_SINCE' => timestamp, 'HTTP_IF_NONE_MATCH' => '4321')

    response.status.should.equal 200
    response.body.should.equal 'TEST'
  end

  should "set a 304 status and truncate body when both If-None-Match and If-Modified-Since hits" do
    timestamp = Time.now.httpdate
    app = conditional_get(lambda { |env|
      [200, {'Last-Modified'=>timestamp, 'Etag'=>'1234'}, ['TEST']] })

    response = Rack::MockRequest.new(app).
      get("/", 'HTTP_IF_MODIFIED_SINCE' => timestamp, 'HTTP_IF_NONE_MATCH' => '1234')

    response.status.should.equal 304
    response.body.should.be.empty
  end

  should "not affect non-GET/HEAD requests" do
    app = conditional_get(lambda { |env|
      [200, {'Etag'=>'1234', 'Content-Type' => 'text/plain'}, ['TEST']] })

    response = Rack::MockRequest.new(app).
      post("/", 'HTTP_IF_NONE_MATCH' => '1234')

    response.status.should.equal 200
    response.body.should.equal 'TEST'
  end

  should "not affect non-200 requests" do
    app = conditional_get(lambda { |env|
      [302, {'Etag'=>'1234', 'Content-Type' => 'text/plain'}, ['TEST']] })

    response = Rack::MockRequest.new(app).
      get("/", 'HTTP_IF_NONE_MATCH' => '1234')

    response.status.should.equal 302
    response.body.should.equal 'TEST'
  end

  should "not affect requests with malformed HTTP_IF_NONE_MATCH" do
    bad_timestamp = Time.now.strftime('%Y-%m-%d %H:%M:%S %z')
    app = conditional_get(lambda { |env|
      [200,{'Last-Modified'=>(Time.now - 3600).httpdate, 'Content-Type' => 'text/plain'}, ['TEST']] })

    response = Rack::MockRequest.new(app).
      get("/", 'HTTP_IF_MODIFIED_SINCE' => bad_timestamp)

    response.status.should.equal 200
    response.body.should.equal 'TEST'
  end

end
