require 'rack/content_type'

describe Rack::ContentType do
  should "set Content-Type to default text/html if none is set" do
    app = lambda { |env| [200, {}, "Hello, World!"] }
    headers = Rack::ContentType.new(app).call({})[1]
    headers['Content-Type'].should.equal 'text/html'
  end

  should "set Content-Type to chosen default if none is set" do
    app = lambda { |env| [200, {}, "Hello, World!"] }
    headers =
      Rack::ContentType.new(app, 'application/octet-stream').call({})[1]
    headers['Content-Type'].should.equal 'application/octet-stream'
  end

  should "not change Content-Type if it is already set" do
    app = lambda { |env| [200, {'Content-Type' => 'foo/bar'}, "Hello, World!"] }
    headers = Rack::ContentType.new(app).call({})[1]
    headers['Content-Type'].should.equal 'foo/bar'
  end

  should "detect Content-Type case insensitive" do
    app = lambda { |env| [200, {'CONTENT-Type' => 'foo/bar'}, "Hello, World!"] }
    headers = Rack::ContentType.new(app).call({})[1]
    headers.to_a.select { |k,v| k.downcase == "content-type" }.
      should.equal [["CONTENT-Type","foo/bar"]]
  end

  should "not set Content-Type on 304 responses" do
    app = lambda { |env| [304, {}, []] }
    response = Rack::ContentType.new(app, "text/html").call({})
    response[1]['Content-Type'].should.equal nil
  end
end
