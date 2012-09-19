require 'rack/lobster'
require 'rack/mock'

describe Rack::Lobster::LambdaLobster do
  should "be a single lambda" do
    Rack::Lobster::LambdaLobster.should.be.kind_of Proc
  end

  should "look like a lobster" do
    res = Rack::MockRequest.new(Rack::Lobster::LambdaLobster).get("/")
    res.should.be.ok
    res.body.should.include "(,(,,(,,,("
    res.body.should.include "?flip"
  end

  should "be flippable" do
    res = Rack::MockRequest.new(Rack::Lobster::LambdaLobster).get("/?flip")
    res.should.be.ok
    res.body.should.include "(,,,(,,(,("
  end
end

describe Rack::Lobster do
  should "look like a lobster" do
    res = Rack::MockRequest.new(Rack::Lobster.new).get("/")
    res.should.be.ok
    res.body.should.include "(,(,,(,,,("
    res.body.should.include "?flip"
    res.body.should.include "crash"
  end

  should "be flippable" do
    res = Rack::MockRequest.new(Rack::Lobster.new).get("/?flip=left")
    res.should.be.ok
    res.body.should.include "(,,,(,,(,("
  end

  should "provide crashing for testing purposes" do
    lambda {
      Rack::MockRequest.new(Rack::Lobster.new).get("/?flip=crash")
    }.should.raise
  end
end
