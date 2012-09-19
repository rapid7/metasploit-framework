require 'rack/showstatus'
require 'rack/mock'

describe Rack::ShowStatus do
  should "provide a default status message" do
    req = Rack::MockRequest.new(
      Rack::ShowStatus.new(lambda{|env|
        [404, {"Content-Type" => "text/plain", "Content-Length" => "0"}, []]
    }))

    res = req.get("/", :lint => true)
    res.should.be.not_found
    res.should.be.not.empty

    res["Content-Type"].should.equal("text/html")
    res.should =~ /404/
    res.should =~ /Not Found/
  end

  should "let the app provide additional information" do
    req = Rack::MockRequest.new(
      Rack::ShowStatus.new(
        lambda{|env|
          env["rack.showstatus.detail"] = "gone too meta."
          [404, {"Content-Type" => "text/plain", "Content-Length" => "0"}, []]
    }))

    res = req.get("/", :lint => true)
    res.should.be.not_found
    res.should.be.not.empty

    res["Content-Type"].should.equal("text/html")
    res.should =~ /404/
    res.should =~ /Not Found/
    res.should =~ /too meta/
  end

  should "not replace existing messages" do
    req = Rack::MockRequest.new(
      Rack::ShowStatus.new(
        lambda{|env|
          [404, {"Content-Type" => "text/plain", "Content-Length" => "4"}, ["foo!"]]
    }))

    res = req.get("/", :lint => true)
    res.should.be.not_found

    res.body.should == "foo!"
  end

  should "pass on original headers" do
    headers = {"WWW-Authenticate" => "Basic blah"}

    req = Rack::MockRequest.new(
      Rack::ShowStatus.new(lambda{|env| [401, headers, []] }))
    res = req.get("/", :lint => true)

    res["WWW-Authenticate"].should.equal("Basic blah")
  end

  should "replace existing messages if there is detail" do
    req = Rack::MockRequest.new(
      Rack::ShowStatus.new(
        lambda{|env|
          env["rack.showstatus.detail"] = "gone too meta."
          [404, {"Content-Type" => "text/plain", "Content-Length" => "4"}, ["foo!"]]
    }))

    res = req.get("/", :lint => true)
    res.should.be.not_found
    res.should.be.not.empty

    res["Content-Type"].should.equal("text/html")
    res["Content-Length"].should.not.equal("4")
    res.should =~ /404/
    res.should =~ /too meta/
    res.body.should.not =~ /foo/
  end
end
