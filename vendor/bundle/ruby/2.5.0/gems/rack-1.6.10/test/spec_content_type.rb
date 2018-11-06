require 'rack/content_type'
require 'rack/lint'
require 'rack/mock'

describe Rack::ContentType do
  def content_type(app, *args)
    Rack::Lint.new Rack::ContentType.new(app, *args)
  end
  
  def request
    Rack::MockRequest.env_for
  end
  
  should "set Content-Type to default text/html if none is set" do
    app = lambda { |env| [200, {}, "Hello, World!"] }
    headers = content_type(app).call(request)[1]
    headers['Content-Type'].should.equal 'text/html'
  end

  should "set Content-Type to chosen default if none is set" do
    app = lambda { |env| [200, {}, "Hello, World!"] }
    headers =
      content_type(app, 'application/octet-stream').call(request)[1]
    headers['Content-Type'].should.equal 'application/octet-stream'
  end

  should "not change Content-Type if it is already set" do
    app = lambda { |env| [200, {'Content-Type' => 'foo/bar'}, "Hello, World!"] }
    headers = content_type(app).call(request)[1]
    headers['Content-Type'].should.equal 'foo/bar'
  end

  should "detect Content-Type case insensitive" do
    app = lambda { |env| [200, {'CONTENT-Type' => 'foo/bar'}, "Hello, World!"] }
    headers = content_type(app).call(request)[1]
    headers.to_a.select { |k,v| k.downcase == "content-type" }.
      should.equal [["CONTENT-Type","foo/bar"]]
  end

  should "not set Content-Type on 304 responses" do
    app = lambda { |env| [304, {}, []] }
    response = content_type(app, "text/html").call(request)
    response[1]['Content-Type'].should.equal nil
  end
end
