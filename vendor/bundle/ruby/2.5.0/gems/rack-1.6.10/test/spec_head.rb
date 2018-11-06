require 'rack/head'
require 'rack/lint'
require 'rack/mock'

describe Rack::Head do

  def test_response(headers = {})
    body = StringIO.new "foo"
    app = lambda do |env|
      [200, {"Content-type" => "test/plain", "Content-length" => "3"}, body]
    end
    request = Rack::MockRequest.env_for("/", headers)
    response = Rack::Lint.new(Rack::Head.new(app)).call(request)

    return response, body
  end

  should "pass GET, POST, PUT, DELETE, OPTIONS, TRACE requests" do
    %w[GET POST PUT DELETE OPTIONS TRACE].each do |type|
      resp, _ = test_response("REQUEST_METHOD" => type)

      resp[0].should.equal(200)
      resp[1].should.equal({"Content-type" => "test/plain", "Content-length" => "3"})
      resp[2].to_enum.to_a.should.equal(["foo"])
    end
  end

  should "remove body from HEAD requests" do
    resp, _ = test_response("REQUEST_METHOD" => "HEAD")

    resp[0].should.equal(200)
    resp[1].should.equal({"Content-type" => "test/plain", "Content-length" => "3"})
    resp[2].to_enum.to_a.should.equal([])
  end

  should "close the body when it is removed" do
    resp, body = test_response("REQUEST_METHOD" => "HEAD")
    resp[0].should.equal(200)
    resp[1].should.equal({"Content-type" => "test/plain", "Content-length" => "3"})
    resp[2].to_enum.to_a.should.equal([])
    body.should.not.be.closed
    resp[2].close
    body.should.be.closed
  end
end
