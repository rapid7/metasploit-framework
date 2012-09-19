require 'stringio'
require 'rack/methodoverride'
require 'rack/mock'

describe Rack::MethodOverride do
  should "not affect GET requests" do
    env = Rack::MockRequest.env_for("/?_method=delete", :method => "GET")
    app = Rack::MethodOverride.new(lambda{|envx| Rack::Request.new(envx) })
    req = app.call(env)

    req.env["REQUEST_METHOD"].should.equal "GET"
  end

  should "modify REQUEST_METHOD for POST requests when _method parameter is set" do
    env = Rack::MockRequest.env_for("/", :method => "POST", :input => "_method=put")
    app = Rack::MethodOverride.new(lambda{|envx| Rack::Request.new(envx) })
    req = app.call(env)

    req.env["REQUEST_METHOD"].should.equal "PUT"
  end

  should "modify REQUEST_METHOD for POST requests when X-HTTP-Method-Override is set" do
    env = Rack::MockRequest.env_for("/",
            :method => "POST",
            "HTTP_X_HTTP_METHOD_OVERRIDE" => "PATCH"
          )
    app = Rack::MethodOverride.new(lambda{|envx| Rack::Request.new(envx) })
    req = app.call(env)

    req.env["REQUEST_METHOD"].should.equal "PATCH"
  end

  should "not modify REQUEST_METHOD if the method is unknown" do
    env = Rack::MockRequest.env_for("/", :method => "POST", :input => "_method=foo")
    app = Rack::MethodOverride.new(lambda{|envx| Rack::Request.new(envx) })
    req = app.call(env)

    req.env["REQUEST_METHOD"].should.equal "POST"
  end

  should "not modify REQUEST_METHOD when _method is nil" do
    env = Rack::MockRequest.env_for("/", :method => "POST", :input => "foo=bar")
    app = Rack::MethodOverride.new(lambda{|envx| Rack::Request.new(envx) })
    req = app.call(env)

    req.env["REQUEST_METHOD"].should.equal "POST"
  end

  should "store the original REQUEST_METHOD prior to overriding" do
    env = Rack::MockRequest.env_for("/",
            :method => "POST",
            :input  => "_method=options")
    app = Rack::MethodOverride.new(lambda{|envx| Rack::Request.new(envx) })
    req = app.call(env)

    req.env["rack.methodoverride.original_method"].should.equal "POST"
  end

  should "not modify REQUEST_METHOD when given invalid multipart form data" do
    input = <<EOF
--AaB03x\r
content-disposition: form-data; name="huge"; filename="huge"\r
EOF
    env = Rack::MockRequest.env_for("/",
                      "CONTENT_TYPE" => "multipart/form-data, boundary=AaB03x",
                      "CONTENT_LENGTH" => input.size,
                      :method => "POST", :input => input)
    app = Rack::MethodOverride.new(lambda{|envx| Rack::Request.new(envx) })
    req = app.call(env)

    req.env["REQUEST_METHOD"].should.equal "POST"
  end
end
