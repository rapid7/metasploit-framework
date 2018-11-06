require 'rack/file'
require 'rack/lint'
require 'rack/mock'

describe Rack::File do
  DOCROOT = File.expand_path(File.dirname(__FILE__)) unless defined? DOCROOT

  def file(*args)
    Rack::Lint.new Rack::File.new(*args)
  end

  should "serve files" do
    res = Rack::MockRequest.new(file(DOCROOT)).get("/cgi/test")

    res.should.be.ok
    res.should =~ /ruby/
  end

  should "set Last-Modified header" do
    res = Rack::MockRequest.new(file(DOCROOT)).get("/cgi/test")

    path = File.join(DOCROOT, "/cgi/test")

    res.should.be.ok
    res["Last-Modified"].should.equal File.mtime(path).httpdate
  end

  should "return 304 if file isn't modified since last serve" do
    path = File.join(DOCROOT, "/cgi/test")
    res = Rack::MockRequest.new(file(DOCROOT)).
      get("/cgi/test", 'HTTP_IF_MODIFIED_SINCE' => File.mtime(path).httpdate)

    res.status.should.equal 304
    res.body.should.be.empty
  end

  should "return the file if it's modified since last serve" do
    path = File.join(DOCROOT, "/cgi/test")
    res = Rack::MockRequest.new(file(DOCROOT)).
      get("/cgi/test", 'HTTP_IF_MODIFIED_SINCE' => (File.mtime(path) - 100).httpdate)

    res.should.be.ok
  end

  should "serve files with URL encoded filenames" do
    res = Rack::MockRequest.new(file(DOCROOT)).get("/cgi/%74%65%73%74") # "/cgi/test"

    res.should.be.ok
    res.should =~ /ruby/
  end

  should "allow safe directory traversal" do
    req = Rack::MockRequest.new(file(DOCROOT))

    res = req.get('/cgi/../cgi/test')
    res.should.be.successful

    res = req.get('.')
    res.should.be.not_found

    res = req.get("test/..")
    res.should.be.not_found
  end

  should "not allow unsafe directory traversal" do
    req = Rack::MockRequest.new(file(DOCROOT))

    res = req.get("/../README.rdoc")
    res.should.be.client_error

    res = req.get("../test/spec_file.rb")
    res.should.be.client_error

    res = req.get("../README.rdoc")
    res.should.be.client_error

    res.should.be.not_found
  end

  should "allow files with .. in their name" do
    req = Rack::MockRequest.new(file(DOCROOT))
    res = req.get("/cgi/..test")
    res.should.be.not_found

    res = req.get("/cgi/test..")
    res.should.be.not_found

    res = req.get("/cgi../test..")
    res.should.be.not_found
  end

  should "not allow unsafe directory traversal with encoded periods" do
    res = Rack::MockRequest.new(file(DOCROOT)).get("/%2E%2E/README")

    res.should.be.client_error?
    res.should.be.not_found
  end

  should "allow safe directory traversal with encoded periods" do
    res = Rack::MockRequest.new(file(DOCROOT)).get("/cgi/%2E%2E/cgi/test")

    res.should.be.successful
  end

  should "404 if it can't find the file" do
    res = Rack::MockRequest.new(file(DOCROOT)).get("/cgi/blubb")

    res.should.be.not_found
  end

  should "detect SystemCallErrors" do
    res = Rack::MockRequest.new(file(DOCROOT)).get("/cgi")

    res.should.be.not_found
  end

  should "return bodies that respond to #to_path" do
    env = Rack::MockRequest.env_for("/cgi/test")
    status, _, body = Rack::File.new(DOCROOT).call(env)

    path = File.join(DOCROOT, "/cgi/test")

    status.should.equal 200
    body.should.respond_to :to_path
    body.to_path.should.equal path
  end

  should "return correct byte range in body" do
    env = Rack::MockRequest.env_for("/cgi/test")
    env["HTTP_RANGE"] = "bytes=22-33"
    res = Rack::MockResponse.new(*file(DOCROOT).call(env))

    res.status.should.equal 206
    res["Content-Length"].should.equal "12"
    res["Content-Range"].should.equal "bytes 22-33/193"
    res.body.should.equal "-*- ruby -*-"
  end

  should "return error for unsatisfiable byte range" do
    env = Rack::MockRequest.env_for("/cgi/test")
    env["HTTP_RANGE"] = "bytes=1234-5678"
    res = Rack::MockResponse.new(*file(DOCROOT).call(env))

    res.status.should.equal 416
    res["Content-Range"].should.equal "bytes */193"
  end

  should "support custom http headers" do
    env = Rack::MockRequest.env_for("/cgi/test")
    status, heads, _ = file(DOCROOT, 'Cache-Control' => 'public, max-age=38',
     'Access-Control-Allow-Origin' => '*').call(env)

    status.should.equal 200
    heads['Cache-Control'].should.equal 'public, max-age=38'
    heads['Access-Control-Allow-Origin'].should.equal '*'
  end

  should "support not add custom http headers if none are supplied" do
    env = Rack::MockRequest.env_for("/cgi/test")
    status, heads, _ = file(DOCROOT).call(env)

    status.should.equal 200
    heads['Cache-Control'].should.equal nil
    heads['Access-Control-Allow-Origin'].should.equal nil
  end

  should "only support GET, HEAD, and OPTIONS requests" do
    req = Rack::MockRequest.new(file(DOCROOT))

    forbidden = %w[post put patch delete]
    forbidden.each do |method|
      res = req.send(method, "/cgi/test")
      res.should.be.client_error
      res.should.be.method_not_allowed
      res.headers['Allow'].split(/, */).sort.should == %w(GET HEAD OPTIONS)
    end

    allowed = %w[get head options]
    allowed.each do |method|
      res = req.send(method, "/cgi/test")
      res.should.be.successful
    end
  end

  should "set Allow correctly for OPTIONS requests" do
    req = Rack::MockRequest.new(file(DOCROOT))
    res = req.options('/cgi/test')
    res.should.be.successful
    res.headers['Allow'].should.not.equal nil
    res.headers['Allow'].split(/, */).sort.should == %w(GET HEAD OPTIONS)
  end

  should "set Content-Length correctly for HEAD requests" do
    req = Rack::MockRequest.new(Rack::Lint.new(Rack::File.new(DOCROOT)))
    res = req.head "/cgi/test"
    res.should.be.successful
    res['Content-Length'].should.equal "193"
  end

  should "default to a mime type of text/plain" do
    req = Rack::MockRequest.new(Rack::Lint.new(Rack::File.new(DOCROOT)))
    res = req.get "/cgi/test"
    res.should.be.successful
    res['Content-Type'].should.equal "text/plain"
  end

  should "allow the default mime type to be set" do
    req = Rack::MockRequest.new(Rack::Lint.new(Rack::File.new(DOCROOT, nil, 'application/octet-stream')))
    res = req.get "/cgi/test"
    res.should.be.successful
    res['Content-Type'].should.equal "application/octet-stream"
  end

  should "not set Content-Type if the mime type is not set" do
    req = Rack::MockRequest.new(Rack::Lint.new(Rack::File.new(DOCROOT, nil, nil)))
    res = req.get "/cgi/test"
    res.should.be.successful
    res['Content-Type'].should.equal nil
  end

end
