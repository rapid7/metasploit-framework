require 'rack/showexceptions'
require 'rack/mock'

describe Rack::ShowExceptions do
  it "catches exceptions" do
    res = nil

    req = Rack::MockRequest.new(
      Rack::ShowExceptions.new(
        lambda{|env| raise RuntimeError }
    ))

    lambda{
      res = req.get("/")
    }.should.not.raise

    res.should.be.a.server_error
    res.status.should.equal 500

    res.should =~ /RuntimeError/
    res.should =~ /ShowExceptions/
  end

  it "responds with plain text on AJAX requests accepting anything but HTML" do
    res = nil

    req = Rack::MockRequest.new(
      Rack::ShowExceptions.new(
        lambda{|env| raise RuntimeError, "It was never supposed to work" }
    ))

    lambda{
      res = req.get("/", "HTTP_X_REQUESTED_WITH" => "XMLHttpRequest")
    }.should.not.raise

    res.should.be.a.server_error
    res.status.should.equal 500

    res.content_type.should.equal "text/plain"

    res.body.should.include "RuntimeError: It was never supposed to work\n"
    res.body.should.include __FILE__
  end

  it "responds with HTML on AJAX requests accepting HTML" do
    res = nil

    req = Rack::MockRequest.new(
      Rack::ShowExceptions.new(
        lambda{|env| raise RuntimeError, "It was never supposed to work" }
    ))

    lambda{
      res = req.get("/", "HTTP_X_REQUESTED_WITH" => "XMLHttpRequest", "HTTP_ACCEPT" => "text/html")
    }.should.not.raise

    res.should.be.a.server_error
    res.status.should.equal 500

    res.content_type.should.equal "text/html"

    res.body.should.include "RuntimeError"
    res.body.should.include "It was never supposed to work"
    res.body.should.include Rack::Utils.escape_html(__FILE__)
  end

  it "handles exceptions without a backtrace" do
    res = nil

    req = Rack::MockRequest.new(
      Rack::ShowExceptions.new(
        lambda{|env| raise RuntimeError, "", [] }
      )
    )

    lambda{
      res = req.get("/")
    }.should.not.raise

    res.should.be.a.server_error
    res.status.should.equal 500

    res.should =~ /RuntimeError/
    res.should =~ /ShowExceptions/
    res.should =~ /unknown location/
  end
end
