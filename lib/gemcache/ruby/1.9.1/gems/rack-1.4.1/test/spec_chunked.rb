require 'rack/chunked'
require 'rack/lint'
require 'rack/mock'

describe Rack::Chunked do
  Enumerator = ::Enumerable::Enumerator unless defined?(Enumerator)

  def chunked(app)
    proc do |env|
      app = Rack::Chunked.new(app)
      Rack::Lint.new(app).call(env).tap do |response|
        # we want to use body like an array, but it only has #each
        response[2] = Enumerator.new(response[2]).to_a
      end
    end
  end
  
  before do
    @env = Rack::MockRequest.
      env_for('/', 'HTTP_VERSION' => '1.1', 'REQUEST_METHOD' => 'GET')
  end

  should 'chunk responses with no Content-Length' do
    app = lambda { |env| [200, {"Content-Type" => "text/plain"}, ['Hello', ' ', 'World!']] }
    response = Rack::MockResponse.new(*chunked(app).call(@env))
    response.headers.should.not.include 'Content-Length'
    response.headers['Transfer-Encoding'].should.equal 'chunked'
    response.body.should.equal "5\r\nHello\r\n1\r\n \r\n6\r\nWorld!\r\n0\r\n\r\n"
  end

  should 'chunks empty bodies properly' do
    app = lambda { |env| [200, {"Content-Type" => "text/plain"}, []] }
    response = Rack::MockResponse.new(*chunked(app).call(@env))
    response.headers.should.not.include 'Content-Length'
    response.headers['Transfer-Encoding'].should.equal 'chunked'
    response.body.should.equal "0\r\n\r\n"
  end

  should 'chunks encoded bodies properly' do
    body = ["\uFFFEHello", " ", "World"].map {|t| t.encode("UTF-16LE") }
    app  = lambda { |env| [200, {"Content-Type" => "text/plain"}, body] }
    response = Rack::MockResponse.new(*chunked(app).call(@env))
    response.headers.should.not.include 'Content-Length'
    response.headers['Transfer-Encoding'].should.equal 'chunked'
    response.body.encoding.to_s.should == "ASCII-8BIT"
    response.body.should.equal "c\r\n\xFE\xFFH\x00e\x00l\x00l\x00o\x00\r\n2\r\n \x00\r\na\r\nW\x00o\x00r\x00l\x00d\x00\r\n0\r\n\r\n"
  end if RUBY_VERSION >= "1.9"

  should 'not modify response when Content-Length header present' do
    app = lambda { |env|
      [200, {"Content-Type" => "text/plain", 'Content-Length'=>'12'}, ['Hello', ' ', 'World!']]
    }
    status, headers, body = chunked(app).call(@env)
    status.should.equal 200
    headers.should.not.include 'Transfer-Encoding'
    headers.should.include 'Content-Length'
    body.join.should.equal 'Hello World!'
  end

  should 'not modify response when client is HTTP/1.0' do
    app = lambda { |env| [200, {"Content-Type" => "text/plain"}, ['Hello', ' ', 'World!']] }
    @env['HTTP_VERSION'] = 'HTTP/1.0'
    status, headers, body = chunked(app).call(@env)
    status.should.equal 200
    headers.should.not.include 'Transfer-Encoding'
    body.join.should.equal 'Hello World!'
  end

  should 'not modify response when Transfer-Encoding header already present' do
    app = lambda { |env|
      [200, {"Content-Type" => "text/plain", 'Transfer-Encoding' => 'identity'}, ['Hello', ' ', 'World!']]
    }
    status, headers, body = chunked(app).call(@env)
    status.should.equal 200
    headers['Transfer-Encoding'].should.equal 'identity'
    body.join.should.equal 'Hello World!'
  end

  [100, 204, 205, 304].each do |status_code|
    should "not modify response when status code is #{status_code}" do
      app = lambda { |env| [status_code, {}, []] }
      status, headers, _ = chunked(app).call(@env)
      status.should.equal status_code
      headers.should.not.include 'Transfer-Encoding'
    end
  end
end
