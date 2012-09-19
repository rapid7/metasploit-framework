begin
require 'rack'
require 'rack/handler/mongrel'
require File.expand_path('../testrequest', __FILE__)
require 'timeout'

Thread.abort_on_exception = true
$tcp_defer_accept_opts = nil
$tcp_cork_opts = nil

describe Rack::Handler::Mongrel do
  extend TestRequest::Helpers

  @server = Mongrel::HttpServer.new(@host='127.0.0.1', @port=9201)
  @server.register('/test',
                  Rack::Handler::Mongrel.new(Rack::Lint.new(TestRequest.new)))
  @server.register('/stream',
                  Rack::Handler::Mongrel.new(Rack::Lint.new(StreamingRequest)))
  @acc = @server.run

  should "respond" do
    lambda {
      GET("/test")
    }.should.not.raise
  end

  should "be a Mongrel" do
    GET("/test")
    status.should.equal 200
    response["SERVER_SOFTWARE"].should =~ /Mongrel/
    response["HTTP_VERSION"].should.equal "HTTP/1.1"
    response["SERVER_PROTOCOL"].should.equal "HTTP/1.1"
    response["SERVER_PORT"].should.equal "9201"
    response["SERVER_NAME"].should.equal "127.0.0.1"
  end

  should "have rack headers" do
    GET("/test")
    response["rack.version"].should.equal [1,1]
    response["rack.multithread"].should.be.true
    response["rack.multiprocess"].should.be.false
    response["rack.run_once"].should.be.false
  end

  should "have CGI headers on GET" do
    GET("/test")
    response["REQUEST_METHOD"].should.equal "GET"
    response["SCRIPT_NAME"].should.equal "/test"
    response["REQUEST_PATH"].should.equal "/test"
    response["PATH_INFO"].should.be.equal ""
    response["QUERY_STRING"].should.equal ""
    response["test.postdata"].should.equal ""

    GET("/test/foo?quux=1")
    response["REQUEST_METHOD"].should.equal "GET"
    response["SCRIPT_NAME"].should.equal "/test"
    response["REQUEST_PATH"].should.equal "/test/foo"
    response["PATH_INFO"].should.equal "/foo"
    response["QUERY_STRING"].should.equal "quux=1"
  end

  should "have CGI headers on POST" do
    POST("/test", {"rack-form-data" => "23"}, {'X-test-header' => '42'})
    status.should.equal 200
    response["REQUEST_METHOD"].should.equal "POST"
    response["SCRIPT_NAME"].should.equal "/test"
    response["REQUEST_PATH"].should.equal "/test"
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

  should "provide a .run" do
    block_ran = false
    Thread.new {
      Rack::Handler::Mongrel.run(lambda {}, {:Host => '127.0.0.1', :Port => 9211}) { |server|
        server.should.be.kind_of Mongrel::HttpServer
        block_ran = true
      }
    }
    sleep 1
    block_ran.should.be.true
  end

  should "provide a .run that maps a hash" do
    block_ran = false
    Thread.new {
      map = {'/'=>lambda{},'/foo'=>lambda{}}
      Rack::Handler::Mongrel.run(map, :map => true, :Host => '127.0.0.1', :Port => 9221) { |server|
        server.should.be.kind_of Mongrel::HttpServer
        server.classifier.uris.size.should.equal 2
        server.classifier.uris.should.not.include '/arf'
        server.classifier.uris.should.include '/'
        server.classifier.uris.should.include '/foo'
        block_ran = true
      }
    }
    sleep 1
    block_ran.should.be.true
  end

  should "provide a .run that maps a urlmap" do
    block_ran = false
    Thread.new {
      map = Rack::URLMap.new({'/'=>lambda{},'/bar'=>lambda{}})
      Rack::Handler::Mongrel.run(map, {:map => true, :Host => '127.0.0.1', :Port => 9231}) { |server|
        server.should.be.kind_of Mongrel::HttpServer
        server.classifier.uris.size.should.equal 2
        server.classifier.uris.should.not.include '/arf'
        server.classifier.uris.should.include '/'
        server.classifier.uris.should.include '/bar'
        block_ran = true
      }
    }
    sleep 1
    block_ran.should.be.true
  end

  should "provide a .run that maps a urlmap restricting by host" do
    block_ran = false
    Thread.new {
      map = Rack::URLMap.new({
        '/' => lambda{},
        '/foo' => lambda{},
        '/bar' => lambda{},
        'http://127.0.0.1/' => lambda{},
        'http://127.0.0.1/bar' => lambda{},
        'http://falsehost/arf' => lambda{},
        'http://falsehost/qux' => lambda{}
      })
      opt = {:map => true, :Port => 9241, :Host => '127.0.0.1'}
      Rack::Handler::Mongrel.run(map, opt) { |server|
        server.should.be.kind_of Mongrel::HttpServer
        server.classifier.uris.should.include '/'
        server.classifier.handler_map['/'].size.should.equal 2
        server.classifier.uris.should.include '/foo'
        server.classifier.handler_map['/foo'].size.should.equal 1
        server.classifier.uris.should.include '/bar'
        server.classifier.handler_map['/bar'].size.should.equal 2
        server.classifier.uris.should.not.include '/qux'
        server.classifier.uris.should.not.include '/arf'
        server.classifier.uris.size.should.equal 3
        block_ran = true
      }
    }
    sleep 1
    block_ran.should.be.true
  end

  should "stream #each part of the response" do
    body = ''
    begin
      Timeout.timeout(1) do
        Net::HTTP.start(@host, @port) do |http|
          get = Net::HTTP::Get.new('/stream')
          http.request(get) do |response|
            response.read_body { |part| body << part }
          end
        end
      end
    rescue Timeout::Error
    end
    body.should.not.be.empty
  end

  @acc.raise Mongrel::StopServer
end

rescue LoadError
  warn "Skipping Rack::Handler::Mongrel tests (Mongrel is required). `gem install mongrel` and try again."
end
