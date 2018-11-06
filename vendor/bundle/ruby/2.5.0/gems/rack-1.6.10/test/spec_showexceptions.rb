require 'rack/showexceptions'
require 'rack/lint'
require 'rack/mock'

describe Rack::ShowExceptions do
  def show_exceptions(app)
    Rack::Lint.new Rack::ShowExceptions.new(app)
  end
  
  it "catches exceptions" do
    res = nil

    req = Rack::MockRequest.new(
      show_exceptions(
        lambda{|env| raise RuntimeError }
    ))

    lambda{
      res = req.get("/", "HTTP_ACCEPT" => "text/html")
    }.should.not.raise

    res.should.be.a.server_error
    res.status.should.equal 500

    res.should =~ /RuntimeError/
    res.should =~ /ShowExceptions/
  end

  it "responds with HTML only to requests accepting HTML" do
    res = nil

    req = Rack::MockRequest.new(
      show_exceptions(
        lambda{|env| raise RuntimeError, "It was never supposed to work" }
    ))

    [
      # Serve text/html when the client accepts text/html
      ["text/html", ["/", {"HTTP_ACCEPT" => "text/html"}]],
      ["text/html", ["/", {"HTTP_ACCEPT" => "*/*"}]],
      # Serve text/plain when the client does not accept text/html
      ["text/plain", ["/"]],
      ["text/plain", ["/", {"HTTP_ACCEPT" => "application/json"}]]
    ].each do |exmime, rargs|
      lambda{
        res = req.get(*rargs)
      }.should.not.raise

      res.should.be.a.server_error
      res.status.should.equal 500

      res.content_type.should.equal exmime

      res.body.should.include "RuntimeError"
      res.body.should.include "It was never supposed to work"

      if exmime == "text/html"
        res.body.should.include '</html>'
      else
        res.body.should.not.include '</html>'
      end
    end
  end

  it "handles exceptions without a backtrace" do
    res = nil

    req = Rack::MockRequest.new(
      show_exceptions(
        lambda{|env| raise RuntimeError, "", [] }
      )
    )

    lambda{
      res = req.get("/", "HTTP_ACCEPT" => "text/html")
    }.should.not.raise

    res.should.be.a.server_error
    res.status.should.equal 500

    res.should =~ /RuntimeError/
    res.should =~ /ShowExceptions/
    res.should =~ /unknown location/
  end
end
