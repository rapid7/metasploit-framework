require 'rack/head'
require 'rack/mock'

describe Rack::Head do
  def test_response(headers = {})
    app = lambda { |env| [200, {"Content-type" => "test/plain", "Content-length" => "3"}, ["foo"]] }
    request = Rack::MockRequest.env_for("/", headers)
    response = Rack::Head.new(app).call(request)

    return response
  end

  should "pass GET, POST, PUT, DELETE, OPTIONS, TRACE requests" do
    %w[GET POST PUT DELETE OPTIONS TRACE].each do |type|
      resp = test_response("REQUEST_METHOD" => type)

      resp[0].should.equal(200)
      resp[1].should.equal({"Content-type" => "test/plain", "Content-length" => "3"})
      resp[2].should.equal(["foo"])
    end
  end

  should "remove body from HEAD requests" do
    resp = test_response("REQUEST_METHOD" => "HEAD")

    resp[0].should.equal(200)
    resp[1].should.equal({"Content-type" => "test/plain", "Content-length" => "3"})
    resp[2].should.equal([])
  end
end
