require 'rack/etag'
require 'rack/lint'
require 'rack/mock'
require 'time'

describe Rack::ETag do
  def etag(app, *args)
    Rack::Lint.new Rack::ETag.new(app, *args)
  end
  
  def request
    Rack::MockRequest.env_for
  end
  
  def sendfile_body
    res = ['Hello World']
    def res.to_path ; "/tmp/hello.txt" ; end
    res
  end

  should "set ETag if none is set if status is 200" do
    app = lambda { |env| [200, {'Content-Type' => 'text/plain'}, ["Hello, World!"]] }
    response = etag(app).call(request)
    response[1]['ETag'].should.equal "W/\"65a8e27d8879283831b664bd8b7f0ad4\""
  end

  should "set ETag if none is set if status is 201" do
    app = lambda { |env| [201, {'Content-Type' => 'text/plain'}, ["Hello, World!"]] }
    response = etag(app).call(request)
    response[1]['ETag'].should.equal "W/\"65a8e27d8879283831b664bd8b7f0ad4\""
  end

  should "set Cache-Control to 'max-age=0, private, must-revalidate' (default) if none is set" do
    app = lambda { |env| [201, {'Content-Type' => 'text/plain'}, ["Hello, World!"]] }
    response = etag(app).call(request)
    response[1]['Cache-Control'].should.equal 'max-age=0, private, must-revalidate'
  end

  should "set Cache-Control to chosen one if none is set" do
    app = lambda { |env| [201, {'Content-Type' => 'text/plain'}, ["Hello, World!"]] }
    response = etag(app, nil, 'public').call(request)
    response[1]['Cache-Control'].should.equal 'public'
  end

  should "set a given Cache-Control even if digest could not be calculated" do
    app = lambda { |env| [200, {'Content-Type' => 'text/plain'}, []] }
    response = etag(app, 'no-cache').call(request)
    response[1]['Cache-Control'].should.equal 'no-cache'
  end

  should "not set Cache-Control if it is already set" do
    app = lambda { |env| [201, {'Content-Type' => 'text/plain', 'Cache-Control' => 'public'}, ["Hello, World!"]] }
    response = etag(app).call(request)
    response[1]['Cache-Control'].should.equal 'public'
  end

  should "not set Cache-Control if directive isn't present" do
    app = lambda { |env| [200, {'Content-Type' => 'text/plain'}, ["Hello, World!"]] }
    response = etag(app, nil, nil).call(request)
    response[1]['Cache-Control'].should.equal nil
  end

  should "not change ETag if it is already set" do
    app = lambda { |env| [200, {'Content-Type' => 'text/plain', 'ETag' => '"abc"'}, ["Hello, World!"]] }
    response = etag(app).call(request)
    response[1]['ETag'].should.equal "\"abc\""
  end

  should "not set ETag if body is empty" do
    app = lambda { |env| [200, {'Content-Type' => 'text/plain', 'Last-Modified' => Time.now.httpdate}, []] }
    response = etag(app).call(request)
    response[1]['ETag'].should.be.nil
  end

  should "not set ETag if Last-Modified is set" do
    app = lambda { |env| [200, {'Content-Type' => 'text/plain', 'Last-Modified' => Time.now.httpdate}, ["Hello, World!"]] }
    response = etag(app).call(request)
    response[1]['ETag'].should.be.nil
  end

  should "not set ETag if a sendfile_body is given" do
    app = lambda { |env| [200, {'Content-Type' => 'text/plain'}, sendfile_body] }
    response = etag(app).call(request)
    response[1]['ETag'].should.be.nil
  end

  should "not set ETag if a status is not 200 or 201" do
    app = lambda { |env| [401, {'Content-Type' => 'text/plain'}, ['Access denied.']] }
    response = etag(app).call(request)
    response[1]['ETag'].should.be.nil
  end

  should "not set ETag if no-cache is given" do
    app = lambda { |env| [200, {'Content-Type' => 'text/plain', 'Cache-Control' => 'no-cache, must-revalidate'}, ['Hello, World!']] }
    response = etag(app).call(request)
    response[1]['ETag'].should.be.nil
  end

  should "close the original body" do
    body = StringIO.new
    app = lambda { |env| [200, {}, body] }
    response = etag(app).call(request)
    body.should.not.be.closed
    response[2].close
    body.should.be.closed
  end
end
