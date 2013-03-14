require 'rack/response'
require 'stringio'

describe Rack::Response do
  should "have sensible default values" do
    response = Rack::Response.new
    status, header, body = response.finish
    status.should.equal 200
    header.should.equal "Content-Type" => "text/html"
    body.each { |part|
      part.should.equal ""
    }

    response = Rack::Response.new
    status, header, body = *response
    status.should.equal 200
    header.should.equal "Content-Type" => "text/html"
    body.each { |part|
      part.should.equal ""
    }
  end

  it "can be written to" do
    response = Rack::Response.new

    _, _, body = response.finish do
      response.write "foo"
      response.write "bar"
      response.write "baz"
    end

    parts = []
    body.each { |part| parts << part }

    parts.should.equal ["foo", "bar", "baz"]
  end

  it "can set and read headers" do
    response = Rack::Response.new
    response["Content-Type"].should.equal "text/html"
    response["Content-Type"] = "text/plain"
    response["Content-Type"].should.equal "text/plain"
  end

  it "can override the initial Content-Type with a different case" do
    response = Rack::Response.new("", 200, "content-type" => "text/plain")
    response["Content-Type"].should.equal "text/plain"
  end

  it "can set cookies" do
    response = Rack::Response.new

    response.set_cookie "foo", "bar"
    response["Set-Cookie"].should.equal "foo=bar"
    response.set_cookie "foo2", "bar2"
    response["Set-Cookie"].should.equal ["foo=bar", "foo2=bar2"].join("\n")
    response.set_cookie "foo3", "bar3"
    response["Set-Cookie"].should.equal ["foo=bar", "foo2=bar2", "foo3=bar3"].join("\n")
  end

  it "can set cookies with the same name for multiple domains" do
    response = Rack::Response.new
    response.set_cookie "foo", {:value => "bar", :domain => "sample.example.com"}
    response.set_cookie "foo", {:value => "bar", :domain => ".example.com"}
    response["Set-Cookie"].should.equal ["foo=bar; domain=sample.example.com", "foo=bar; domain=.example.com"].join("\n")
  end

  it "formats the Cookie expiration date accordingly to RFC 2109" do
    response = Rack::Response.new

    response.set_cookie "foo", {:value => "bar", :expires => Time.now+10}
    response["Set-Cookie"].should.match(
      /expires=..., \d\d-...-\d\d\d\d \d\d:\d\d:\d\d .../)
  end

  it "can set secure cookies" do
    response = Rack::Response.new
    response.set_cookie "foo", {:value => "bar", :secure => true}
    response["Set-Cookie"].should.equal "foo=bar; secure"
  end

  it "can set http only cookies" do
    response = Rack::Response.new
    response.set_cookie "foo", {:value => "bar", :httponly => true}
    response["Set-Cookie"].should.equal "foo=bar; HttpOnly"
  end

  it "can delete cookies" do
    response = Rack::Response.new
    response.set_cookie "foo", "bar"
    response.set_cookie "foo2", "bar2"
    response.delete_cookie "foo"
    response["Set-Cookie"].should.equal [
      "foo2=bar2",
      "foo=; expires=Thu, 01-Jan-1970 00:00:00 GMT"
    ].join("\n")
  end

  it "can delete cookies with the same name from multiple domains" do
    response = Rack::Response.new
    response.set_cookie "foo", {:value => "bar", :domain => "sample.example.com"}
    response.set_cookie "foo", {:value => "bar", :domain => ".example.com"}
    response["Set-Cookie"].should.equal ["foo=bar; domain=sample.example.com", "foo=bar; domain=.example.com"].join("\n")
    response.delete_cookie "foo", :domain => ".example.com"
    response["Set-Cookie"].should.equal ["foo=bar; domain=sample.example.com", "foo=; domain=.example.com; expires=Thu, 01-Jan-1970 00:00:00 GMT"].join("\n")
    response.delete_cookie "foo", :domain => "sample.example.com"
    response["Set-Cookie"].should.equal ["foo=; domain=.example.com; expires=Thu, 01-Jan-1970 00:00:00 GMT",
                                         "foo=; domain=sample.example.com; expires=Thu, 01-Jan-1970 00:00:00 GMT"].join("\n")
  end

  it "can delete cookies with the same name with different paths" do
    response = Rack::Response.new
    response.set_cookie "foo", {:value => "bar", :path => "/"}
    response.set_cookie "foo", {:value => "bar", :path => "/path"}
    response["Set-Cookie"].should.equal ["foo=bar; path=/",
                                         "foo=bar; path=/path"].join("\n")

    response.delete_cookie "foo", :path => "/path"
    response["Set-Cookie"].should.equal ["foo=bar; path=/",
                                         "foo=; path=/path; expires=Thu, 01-Jan-1970 00:00:00 GMT"].join("\n")
  end

  it "can do redirects" do
    response = Rack::Response.new
    response.redirect "/foo"
    status, header, body = response.finish
    status.should.equal 302
    header["Location"].should.equal "/foo"

    response = Rack::Response.new
    response.redirect "/foo", 307
    status, header, body = response.finish

    status.should.equal 307
  end

  it "has a useful constructor" do
    r = Rack::Response.new("foo")
    status, header, body = r.finish
    str = ""; body.each { |part| str << part }
    str.should.equal "foo"

    r = Rack::Response.new(["foo", "bar"])
    status, header, body = r.finish
    str = ""; body.each { |part| str << part }
    str.should.equal "foobar"

    object_with_each = Object.new
    def object_with_each.each
      yield "foo"
      yield "bar"
    end
    r = Rack::Response.new(object_with_each)
    r.write "foo"
    status, header, body = r.finish
    str = ""; body.each { |part| str << part }
    str.should.equal "foobarfoo"

    r = Rack::Response.new([], 500)
    r.status.should.equal 500

    r = Rack::Response.new([], "200 OK")
    r.status.should.equal 200
  end

  it "has a constructor that can take a block" do
    r = Rack::Response.new { |res|
      res.status = 404
      res.write "foo"
    }
    status, _, body = r.finish
    str = ""; body.each { |part| str << part }
    str.should.equal "foo"
    status.should.equal 404
  end

  it "doesn't return invalid responses" do
    r = Rack::Response.new(["foo", "bar"], 204)
    _, header, body = r.finish
    str = ""; body.each { |part| str << part }
    str.should.be.empty
    header["Content-Type"].should.equal nil
    header['Content-Length'].should.equal nil

    lambda {
      Rack::Response.new(Object.new)
    }.should.raise(TypeError).
      message.should =~ /stringable or iterable required/
  end

  it "knows if it's empty" do
    r = Rack::Response.new
    r.should.be.empty
    r.write "foo"
    r.should.not.be.empty

    r = Rack::Response.new
    r.should.be.empty
    r.finish
    r.should.be.empty

    r = Rack::Response.new
    r.should.be.empty
    r.finish { }
    r.should.not.be.empty
  end

  should "provide access to the HTTP status" do
    res = Rack::Response.new
    res.status = 200
    res.should.be.successful
    res.should.be.ok

    res.status = 400
    res.should.not.be.successful
    res.should.be.client_error
    res.should.be.bad_request

    res.status = 404
    res.should.not.be.successful
    res.should.be.client_error
    res.should.be.not_found

    res.status = 405
    res.should.not.be.successful
    res.should.be.client_error
    res.should.be.method_not_allowed

    res.status = 422
    res.should.not.be.successful
    res.should.be.client_error
    res.should.be.unprocessable

    res.status = 501
    res.should.not.be.successful
    res.should.be.server_error

    res.status = 307
    res.should.be.redirect
  end

  should "provide access to the HTTP headers" do
    res = Rack::Response.new
    res["Content-Type"] = "text/yaml"

    res.should.include "Content-Type"
    res.headers["Content-Type"].should.equal "text/yaml"
    res["Content-Type"].should.equal "text/yaml"
    res.content_type.should.equal "text/yaml"
    res.content_length.should.be.nil
    res.location.should.be.nil
  end

  it "does not add or change Content-Length when #finish()ing" do
    res = Rack::Response.new
    res.status = 200
    res.finish
    res.headers["Content-Length"].should.be.nil

    res = Rack::Response.new
    res.status = 200
    res.headers["Content-Length"] = "10"
    res.finish
    res.headers["Content-Length"].should.equal "10"
  end

  it "updates Content-Length when body appended to using #write" do
    res = Rack::Response.new
    res.status = 200
    res.headers["Content-Length"].should.be.nil
    res.write "Hi"
    res.headers["Content-Length"].should.equal "2"
    res.write " there"
    res.headers["Content-Length"].should.equal "8"
  end

  it "calls close on #body" do
    res = Rack::Response.new
    res.body = StringIO.new
    res.close
    res.body.should.be.closed
  end
end
