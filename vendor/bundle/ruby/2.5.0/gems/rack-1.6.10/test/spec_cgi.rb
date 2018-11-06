begin
require File.expand_path('../testrequest', __FILE__)
require 'rack/handler/cgi'

describe Rack::Handler::CGI do
  extend TestRequest::Helpers

  @host = '127.0.0.1'
  @port = 9203

  if `which lighttpd` && !$?.success?
    raise "lighttpd not found"
  end

  # Keep this first.
  $pid = fork {
    ENV['RACK_ENV'] = 'deployment'
    ENV['RUBYLIB'] = [
      File.expand_path('../../lib', __FILE__),
      ENV['RUBYLIB'],
    ].compact.join(':')

    Dir.chdir(File.expand_path("../cgi", __FILE__)) do
      exec "lighttpd -D -f lighttpd.conf"
    end
  }

  should "respond" do
    sleep 1
    GET("/test")
    response.should.not.be.nil
  end

  should "be a lighttpd" do
    GET("/test")
    status.should.equal 200
    response["SERVER_SOFTWARE"].should =~ /lighttpd/
    response["HTTP_VERSION"].should.equal "HTTP/1.1"
    response["SERVER_PROTOCOL"].should.equal "HTTP/1.1"
    response["SERVER_PORT"].should.equal @port.to_s
    response["SERVER_NAME"].should.equal @host
  end

  should "have rack headers" do
    GET("/test")
    response["rack.version"].should.equal([1,3])
    response["rack.multithread"].should.be.false
    response["rack.multiprocess"].should.be.true
    response["rack.run_once"].should.be.true
  end

  should "have CGI headers on GET" do
    GET("/test")
    response["REQUEST_METHOD"].should.equal "GET"
    response["SCRIPT_NAME"].should.equal "/test"
    response["REQUEST_PATH"].should.equal "/"
    response["PATH_INFO"].should.be.nil
    response["QUERY_STRING"].should.equal ""
    response["test.postdata"].should.equal ""

    GET("/test/foo?quux=1")
    response["REQUEST_METHOD"].should.equal "GET"
    response["SCRIPT_NAME"].should.equal "/test"
    response["REQUEST_PATH"].should.equal "/"
    response["PATH_INFO"].should.equal "/foo"
    response["QUERY_STRING"].should.equal "quux=1"
  end

  should "have CGI headers on POST" do
    POST("/test", {"rack-form-data" => "23"}, {'X-test-header' => '42'})
    status.should.equal 200
    response["REQUEST_METHOD"].should.equal "POST"
    response["SCRIPT_NAME"].should.equal "/test"
    response["REQUEST_PATH"].should.equal "/"
    response["QUERY_STRING"].should.equal ""
    response["HTTP_X_TEST_HEADER"].should.equal "42"
    response["test.postdata"].should.equal "rack-form-data=23"
  end

  should "support HTTP auth" do
    GET("/test", {:user => "ruth", :passwd => "secret"})
    response["HTTP_AUTHORIZATION"].should.equal "Basic cnV0aDpzZWNyZXQ="
  end

  should "set status" do
    GET("/test?secret")
    status.should.equal 403
    response["rack.url_scheme"].should.equal "http"
  end

  # Keep this last.
  should "shutdown" do
    Process.kill 15, $pid
    Process.wait($pid).should == $pid
  end
end

rescue RuntimeError
  $stderr.puts "Skipping Rack::Handler::CGI tests (lighttpd is required). Install lighttpd and try again."
rescue NotImplementedError
  $stderr.puts "Your Ruby implemenation or platform does not support fork. Skipping Rack::Handler::CGI tests."
end
