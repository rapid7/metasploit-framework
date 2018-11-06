require 'rack/lobster'
require 'rack/lint'
require 'rack/mock'

module LobsterHelpers
  def lobster
    Rack::MockRequest.new Rack::Lint.new(Rack::Lobster.new)
  end

  def lambda_lobster
    Rack::MockRequest.new Rack::Lint.new(Rack::Lobster::LambdaLobster)
  end
end

describe Rack::Lobster::LambdaLobster do
  extend LobsterHelpers
  
  should "be a single lambda" do
    Rack::Lobster::LambdaLobster.should.be.kind_of Proc
  end

  should "look like a lobster" do
    res = lambda_lobster.get("/")
    res.should.be.ok
    res.body.should.include "(,(,,(,,,("
    res.body.should.include "?flip"
  end

  should "be flippable" do
    res = lambda_lobster.get("/?flip")
    res.should.be.ok
    res.body.should.include "(,,,(,,(,("
  end
end

describe Rack::Lobster do
  extend LobsterHelpers
  
  should "look like a lobster" do
    res = lobster.get("/")
    res.should.be.ok
    res.body.should.include "(,(,,(,,,("
    res.body.should.include "?flip"
    res.body.should.include "crash"
  end

  should "be flippable" do
    res = lobster.get("/?flip=left")
    res.should.be.ok
    res.body.should.include "),,,),,),)"
  end

  should "provide crashing for testing purposes" do
    lambda {
      lobster.get("/?flip=crash")
    }.should.raise
  end
end
