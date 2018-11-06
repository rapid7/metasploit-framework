require 'rack/showstatus'
require 'rack/lint'
require 'rack/mock'
require 'rack/utils'

describe Rack::ShowStatus do
  def show_status(app)
    Rack::Lint.new Rack::ShowStatus.new(app)
  end
  
  should "provide a default status message" do
    req = Rack::MockRequest.new(
      show_status(lambda{|env|
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
      show_status(
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

  should "escape error" do
    detail = "<script>alert('hi \"')</script>"
    req = Rack::MockRequest.new(
      show_status(
        lambda{|env|
          env["rack.showstatus.detail"] = detail
          [500, {"Content-Type" => "text/plain", "Content-Length" => "0"}, []]
    }))

    res = req.get("/", :lint => true)
    res.should.be.not.empty

    res["Content-Type"].should.equal("text/html")
    res.should =~ /500/
    res.should.not.include detail
    res.body.should.include Rack::Utils.escape_html(detail)
  end

  should "not replace existing messages" do
    req = Rack::MockRequest.new(
      show_status(
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
      show_status(lambda{|env| [401, headers, []] }))
    res = req.get("/", :lint => true)

    res["WWW-Authenticate"].should.equal("Basic blah")
  end

  should "replace existing messages if there is detail" do
    req = Rack::MockRequest.new(
      show_status(
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
