require 'rack/directory'
require 'rack/mock'

describe Rack::Directory do
  DOCROOT = File.expand_path(File.dirname(__FILE__)) unless defined? DOCROOT
  FILE_CATCH = proc{|env| [200, {'Content-Type'=>'text/plain', "Content-Length" => "7"}, ['passed!']] }
  app = Rack::Directory.new DOCROOT, FILE_CATCH

  should "serve directory indices" do
    res = Rack::MockRequest.new(Rack::Lint.new(app)).
      get("/cgi/")

    res.should.be.ok
    res.should =~ /<html><head>/
  end

  should "pass to app if file found" do
    res = Rack::MockRequest.new(Rack::Lint.new(app)).
      get("/cgi/test")

    res.should.be.ok
    res.should =~ /passed!/
  end

  should "serve uri with URL encoded filenames" do
    res = Rack::MockRequest.new(Rack::Lint.new(app)).
      get("/%63%67%69/") # "/cgi/test"

    res.should.be.ok
    res.should =~ /<html><head>/

    res = Rack::MockRequest.new(Rack::Lint.new(app)).
      get("/cgi/%74%65%73%74") # "/cgi/test"

    res.should.be.ok
    res.should =~ /passed!/
  end

  should "not allow directory traversal" do
    res = Rack::MockRequest.new(Rack::Lint.new(app)).
      get("/cgi/../test")

    res.should.be.forbidden

    res = Rack::MockRequest.new(Rack::Lint.new(app)).
      get("/cgi/%2E%2E/test")

    res.should.be.forbidden
  end

  should "404 if it can't find the file" do
    res = Rack::MockRequest.new(Rack::Lint.new(app)).
      get("/cgi/blubb")

    res.should.be.not_found
  end

  should "uri escape path parts" do # #265, properly escape file names
    mr = Rack::MockRequest.new(Rack::Lint.new(app))

    res = mr.get("/cgi/test%2bdirectory")

    res.should.be.ok
    res.body.should =~ %r[/cgi/test%2Bdirectory/test%2Bfile]

    res = mr.get("/cgi/test%2bdirectory/test%2bfile")
    res.should.be.ok
  end
end
