require File.expand_path('../helper', __FILE__)
require 'date'
require 'json'

class HelpersTest < Minitest::Test
  def test_default
    assert true
  end

  def status_app(code, &block)
    code += 2 if [204, 205, 304].include? code
    block ||= proc { }
    mock_app do
      get('/') do
        status code
        instance_eval(&block).inspect
      end
    end
    get '/'
  end

  describe 'status' do
    it 'sets the response status code' do
      status_app 207
      assert_equal 207, response.status
    end
  end

  describe 'not_found?' do
    it 'is true for status == 404' do
      status_app(404) { not_found? }
      assert_body 'true'
    end

    it 'is false for status gt 404' do
      status_app(405) { not_found? }
      assert_body 'false'
    end

    it 'is false for status lt 404' do
      status_app(403) { not_found? }
      assert_body 'false'
    end
  end

  describe 'informational?' do
    it 'is true for 1xx status' do
      status_app(100 + rand(100)) { informational? }
      assert_body 'true'
    end

    it 'is false for status > 199' do
      status_app(200 + rand(400)) { informational? }
      assert_body 'false'
    end
  end

  describe 'success?' do
    it 'is true for 2xx status' do
      status_app(200 + rand(100)) { success? }
      assert_body 'true'
    end

    it 'is false for status < 200' do
      status_app(100 + rand(100)) { success? }
      assert_body 'false'
    end

    it 'is false for status > 299' do
      status_app(300 + rand(300)) { success? }
      assert_body 'false'
    end
  end

  describe 'redirect?' do
    it 'is true for 3xx status' do
      status_app(300 + rand(100)) { redirect? }
      assert_body 'true'
    end

    it 'is false for status < 300' do
      status_app(200 + rand(100)) { redirect? }
      assert_body 'false'
    end

    it 'is false for status > 399' do
      status_app(400 + rand(200)) { redirect? }
      assert_body 'false'
    end
  end

  describe 'client_error?' do
    it 'is true for 4xx status' do
      status_app(400 + rand(100)) { client_error? }
      assert_body 'true'
    end

    it 'is false for status < 400' do
      status_app(200 + rand(200)) { client_error? }
      assert_body 'false'
    end

    it 'is false for status > 499' do
      status_app(500 + rand(100)) { client_error? }
      assert_body 'false'
    end
  end

  describe 'server_error?' do
    it 'is true for 5xx status' do
      status_app(500 + rand(100)) { server_error? }
      assert_body 'true'
    end

    it 'is false for status < 500' do
      status_app(200 + rand(300)) { server_error? }
      assert_body 'false'
    end
  end

  describe 'body' do
    it 'takes a block for deferred body generation' do
      mock_app do
        get('/') { body { 'Hello World' } }
      end

      get '/'
      assert_equal 'Hello World', body
    end

    it 'takes a String, Array, or other object responding to #each' do
      mock_app { get('/') { body 'Hello World' } }

      get '/'
      assert_equal 'Hello World', body
    end

    it 'can be used with other objects' do
      mock_app do
        get '/' do
          body :hello => 'from json'
        end

        after do
          if Hash === response.body
            body response.body[:hello]
          end
        end
      end

      get '/'
      assert_body 'from json'
    end

    it 'can be set in after filter' do
      mock_app do
        get('/') { body 'route'  }
        after    { body 'filter' }
      end

      get '/'
      assert_body 'filter'
    end
  end

  describe 'redirect' do
    it 'uses a 302 when only a path is given' do
      mock_app do
        get('/') do
          redirect '/foo'
          fail 'redirect should halt'
        end
      end

      get '/'
      assert_equal 302, status
      assert_equal '', body
      assert_equal 'http://example.org/foo', response['Location']
    end

    it 'uses the code given when specified' do
      mock_app do
        get('/') do
          redirect '/foo', 301
          fail 'redirect should halt'
        end
      end

      get '/'
      assert_equal 301, status
      assert_equal '', body
      assert_equal 'http://example.org/foo', response['Location']
    end

    it 'redirects back to request.referer when passed back' do
      mock_app { get('/try_redirect') { redirect back } }

      request = Rack::MockRequest.new(@app)
      response = request.get('/try_redirect', 'HTTP_REFERER' => '/foo')
      assert_equal 302, response.status
      assert_equal 'http://example.org/foo', response['Location']
    end

    it 'redirects using a non-standard HTTP port' do
      mock_app { get('/') { redirect '/foo' } }

      request = Rack::MockRequest.new(@app)
      response = request.get('/', 'SERVER_PORT' => '81')
      assert_equal 'http://example.org:81/foo', response['Location']
    end

    it 'redirects using a non-standard HTTPS port' do
      mock_app { get('/') { redirect '/foo' } }

      request = Rack::MockRequest.new(@app)
      response = request.get('/', 'SERVER_PORT' => '444')
      assert_equal 'http://example.org:444/foo', response['Location']
    end

    it 'uses 303 for post requests if request is HTTP 1.1' do
      mock_app { post('/') { redirect '/'} }
      post('/', {}, 'HTTP_VERSION' => 'HTTP/1.1')
      assert_equal 303, status
      assert_equal '', body
      assert_equal 'http://example.org/', response['Location']
    end

    it 'uses 302 for post requests if request is HTTP 1.0' do
      mock_app { post('/') { redirect '/'} }
      post('/', {}, 'HTTP_VERSION' => 'HTTP/1.0')
      assert_equal 302, status
      assert_equal '', body
      assert_equal 'http://example.org/', response['Location']
    end

    it 'works behind a reverse proxy' do
      mock_app { get('/') { redirect '/foo' } }

      request = Rack::MockRequest.new(@app)
      response = request.get('/', 'HTTP_X_FORWARDED_HOST' => 'example.com', 'SERVER_PORT' => '8080')
      assert_equal 'http://example.com/foo', response['Location']
    end

    it 'accepts absolute URIs' do
      mock_app do
        get('/') do
          redirect 'http://google.com'
          fail 'redirect should halt'
        end
      end

      get '/'
      assert_equal 302, status
      assert_equal '', body
      assert_equal 'http://google.com', response['Location']
    end

    it 'accepts absolute URIs with a different schema' do
      mock_app do
        get('/') do
          redirect 'mailto:jsmith@example.com'
          fail 'redirect should halt'
        end
      end

      get '/'
      assert_equal 302, status
      assert_equal '', body
      assert_equal 'mailto:jsmith@example.com', response['Location']
    end

    it 'accepts a URI object instead of a String' do
      mock_app do
        get('/') { redirect URI.parse('http://sinatrarb.com') }
      end

      get '/'
      assert_equal 302, status
      assert_equal '', body
      assert_equal 'http://sinatrarb.com', response['Location']
    end
  end

  describe 'error' do
    it 'sets a status code and halts' do
      mock_app do
        get('/') do
          error 501
          fail 'error should halt'
        end
      end

      get '/'
      assert_equal 501, status
      assert_equal '', body
    end

    it 'takes an optional body' do
      mock_app do
        get('/') do
          error 501, 'FAIL'
          fail 'error should halt'
        end
      end

      get '/'
      assert_equal 501, status
      assert_equal 'FAIL', body
    end

    it 'should not invoke error handler when setting status inside an error handler' do
      mock_app do
        disable :raise_errors
        not_found do
          body "not_found handler"
          status 404
        end

        error do
          body "error handler"
          status 404
        end

        get '/' do
          raise
        end
      end

      get '/'
      assert_equal 404, status
      assert_equal 'error handler', body
    end

    it 'should not reset the content-type to html for error handlers' do
      mock_app do
        disable :raise_errors
        before    { content_type "application/json" }
        not_found { JSON.dump("error" => "Not Found") }
      end

      get '/'
      assert_equal 404, status
      assert_equal 'application/json', response.content_type
    end

    it 'should not invoke error handler when halting with 500 inside an error handler' do
      mock_app do
        disable :raise_errors
        not_found do
          body "not_found handler"
          halt 404
        end

        error do
          body "error handler"
          halt 404
        end

        get '/' do
          raise
        end
      end

      get '/'
      assert_equal 404, status
      assert_equal 'error handler', body
    end

    it 'should not invoke not_found handler when halting with 404 inside a not found handler' do
      mock_app do
        disable :raise_errors

        not_found do
          body "not_found handler"
          halt 500
        end

        error do
          body "error handler"
          halt 500
        end
      end

      get '/'
      assert_equal 500, status
      assert_equal 'not_found handler', body
    end

    it 'uses a 500 status code when first argument is a body' do
      mock_app do
        get('/') do
          error 'FAIL'
          fail 'error should halt'
        end
      end

      get '/'
      assert_equal 500, status
      assert_equal 'FAIL', body
    end
  end

  describe 'not_found' do
    it 'halts with a 404 status' do
      mock_app do
        get('/') do
          not_found
          fail 'not_found should halt'
        end
      end

      get '/'
      assert_equal 404, status
      assert_equal '', body
    end

    it 'does not set a X-Cascade header' do
      mock_app do
        get('/') do
          not_found
          fail 'not_found should halt'
        end
      end

      get '/'
      assert_equal 404, status
      assert_equal nil, response.headers['X-Cascade']
    end
  end

  describe 'headers' do
    it 'sets headers on the response object when given a Hash' do
      mock_app do
        get('/') do
          headers 'X-Foo' => 'bar', 'X-Baz' => 'bling'
          'kthx'
        end
      end

      get '/'
      assert ok?
      assert_equal 'bar', response['X-Foo']
      assert_equal 'bling', response['X-Baz']
      assert_equal 'kthx', body
    end

    it 'returns the response headers hash when no hash provided' do
      mock_app do
        get('/') do
          headers['X-Foo'] = 'bar'
          'kthx'
        end
      end

      get '/'
      assert ok?
      assert_equal 'bar', response['X-Foo']
    end
  end

  describe 'session' do
    it 'uses the existing rack.session' do
      mock_app do
        get('/') do
          session[:foo]
        end
      end

      get('/', {}, { 'rack.session' => { :foo => 'bar' } })
      assert_equal 'bar', body
    end

    it 'creates a new session when none provided' do
      mock_app do
        enable :sessions

        get('/') do
          assert session[:foo].nil?
          session[:foo] = 'bar'
          redirect '/hi'
        end

        get('/hi') do
          "hi #{session[:foo]}"
        end
      end

      get '/'
      follow_redirect!
      assert_equal 'hi bar', body
    end

    it 'inserts session middleware' do
      mock_app do
        enable :sessions

        get('/') do
          assert env['rack.session']
          assert env['rack.session.options']
          'ok'
        end
      end

      get '/'
      assert_body 'ok'
    end

    it 'sets a default session secret' do
      mock_app do
        enable :sessions

        get('/') do
          secret = env['rack.session.options'][:secret]
          assert secret
          assert_equal secret, settings.session_secret
          'ok'
        end
      end

      get '/'
      assert_body 'ok'
    end

    it 'allows disabling session secret' do
      mock_app do
        enable :sessions
        disable :session_secret

        get('/') do
          assert !env['rack.session.options'].include?(:session_secret)
          'ok'
        end
      end

      # Silence warnings since Rack::Session::Cookie complains about the non-present session secret
      silence_warnings do
        get '/'
      end
      assert_body 'ok'
    end

    it 'accepts an options hash' do
      mock_app do
        set :sessions, :foo => :bar

        get('/') do
          assert_equal env['rack.session.options'][:foo], :bar
          'ok'
        end
      end

      get '/'
      assert_body 'ok'
    end
  end

  describe 'mime_type' do
    include Sinatra::Helpers

    it "looks up mime types in Rack's MIME registry" do
      Rack::Mime::MIME_TYPES['.foo'] = 'application/foo'
      assert_equal 'application/foo', mime_type('foo')
      assert_equal 'application/foo', mime_type('.foo')
      assert_equal 'application/foo', mime_type(:foo)
    end

    it 'returns nil when given nil' do
      assert mime_type(nil).nil?
    end

    it 'returns nil when media type not registered' do
      assert mime_type(:bizzle).nil?
    end

    it 'returns the argument when given a media type string' do
      assert_equal 'text/plain', mime_type('text/plain')
    end

    it 'turns AcceptEntry into String' do
      type = mime_type(Sinatra::Request::AcceptEntry.new('text/plain'))
      assert_equal String, type.class
      assert_equal 'text/plain', type
    end
  end

  test 'Base.mime_type registers mime type' do
    mock_app do
      mime_type :foo, 'application/foo'

      get('/') do
        "foo is #{mime_type(:foo)}"
      end
    end

    get '/'
    assert_equal 'foo is application/foo', body
  end

  describe 'content_type' do
    it 'sets the Content-Type header' do
      mock_app do
        get('/') do
          content_type 'text/plain'
          'Hello World'
        end
      end

      get '/'
      assert_equal 'text/plain;charset=utf-8', response['Content-Type']
      assert_equal 'Hello World', body
    end

    it 'takes media type parameters (like charset=)' do
      mock_app do
        get('/') do
          content_type 'text/html', :charset => 'latin1'
          "<h1>Hello, World</h1>"
        end
      end

      get '/'
      assert ok?
      assert_equal 'text/html;charset=latin1', response['Content-Type']
      assert_equal "<h1>Hello, World</h1>", body
    end

    it "looks up symbols in Rack's mime types dictionary" do
      Rack::Mime::MIME_TYPES['.foo'] = 'application/foo'
      mock_app do
        get('/foo.xml') do
          content_type :foo
          "I AM FOO"
        end
      end

      get '/foo.xml'
      assert ok?
      assert_equal 'application/foo', response['Content-Type']
      assert_equal 'I AM FOO', body
    end

    it 'fails when no mime type is registered for the argument provided' do
      mock_app do
        get('/foo.xml') do
          content_type :bizzle
          "I AM FOO"
        end
      end

      assert_raises(RuntimeError) { get '/foo.xml' }
    end

    it 'only sets default charset for specific mime types' do
      tests_ran = false
      mock_app do
        mime_type :foo, 'text/foo'
        mime_type :bar, 'application/bar'
        mime_type :baz, 'application/baz'
        add_charset << mime_type(:baz)
        get('/') do
          assert_equal content_type(:txt),    'text/plain;charset=utf-8'
          assert_equal content_type(:css),    'text/css;charset=utf-8'
          assert_equal content_type(:html),   'text/html;charset=utf-8'
          assert_equal content_type(:foo),    'text/foo;charset=utf-8'
          assert_equal content_type(:xml),    'application/xml;charset=utf-8'
          assert_equal content_type(:xhtml),  'application/xhtml+xml;charset=utf-8'
          assert_equal content_type(:js),     'application/javascript;charset=utf-8'
          assert_equal content_type(:json),   'application/json'
          assert_equal content_type(:bar),    'application/bar'
          assert_equal content_type(:png),    'image/png'
          assert_equal content_type(:baz),    'application/baz;charset=utf-8'
          tests_ran = true
          "done"
        end
      end

      get '/'
      assert tests_ran
    end

    it 'handles already present params' do
      mock_app do
        get('/') do
          content_type 'foo/bar;level=1', :charset => 'utf-8'
          'ok'
        end
      end

      get '/'
      assert_equal 'foo/bar;level=1, charset=utf-8', response['Content-Type']
    end

    it 'does not add charset if present' do
      mock_app do
        get('/') do
          content_type 'text/plain;charset=utf-16'
          'ok'
        end
      end

      get '/'
      assert_equal 'text/plain;charset=utf-16', response['Content-Type']
    end

    it 'properly encodes parameters with delimiter characters' do
      mock_app do
        before '/comma' do
          content_type 'image/png', :comment => 'Hello, world!'
        end
        before '/semicolon' do
          content_type 'image/png', :comment => 'semi;colon'
        end
        before '/quote' do
          content_type 'image/png', :comment => '"Whatever."'
        end

        get('*') { 'ok' }
      end

      get '/comma'
      assert_equal 'image/png;comment="Hello, world!"', response['Content-Type']
      get '/semicolon'
      assert_equal 'image/png;comment="semi;colon"', response['Content-Type']
      get '/quote'
      assert_equal 'image/png;comment="\"Whatever.\""', response['Content-Type']
    end
  end

  describe 'attachment' do
    def attachment_app(filename=nil)
      mock_app do
        get('/attachment') do
          attachment filename
          response.write("<sinatra></sinatra>")
        end
      end
    end

    it 'sets the Content-Type response header' do
      attachment_app('test.xml')
      get '/attachment'
      assert_equal 'application/xml;charset=utf-8', response['Content-Type']
      assert_equal '<sinatra></sinatra>', body
    end

    it 'sets the Content-Type response header without extname' do
      attachment_app('test')
      get '/attachment'
      assert_equal 'text/html;charset=utf-8', response['Content-Type']
      assert_equal '<sinatra></sinatra>', body
    end

    it 'sets the Content-Type response header with extname' do
      mock_app do
        get('/attachment') do
          content_type :atom
          attachment 'test.xml'
          response.write("<sinatra></sinatra>")
        end
      end

      get '/attachment'
      assert_equal 'application/atom+xml', response['Content-Type']
      assert_equal '<sinatra></sinatra>', body
    end

  end

  describe 'send_file' do
    setup do
      @file = File.dirname(__FILE__) + '/file.txt'
      File.open(@file, 'wb') { |io| io.write('Hello World') }
    end

    def teardown
      File.unlink @file
      @file = nil
    end

    def send_file_app(opts={})
      path = @file
      mock_app {
        get '/file.txt' do
          send_file path, opts
        end
      }
    end

    it "sends the contents of the file" do
      send_file_app
      get '/file.txt'
      assert ok?
      assert_equal 'Hello World', body
    end

    it 'sets the Content-Type response header if a mime-type can be located' do
      send_file_app
      get '/file.txt'
      assert_equal 'text/plain;charset=utf-8', response['Content-Type']
    end

    it 'sets the Content-Type response header if type option is set to a file extension' do
      send_file_app :type => 'html'
      get '/file.txt'
      assert_equal 'text/html;charset=utf-8', response['Content-Type']
    end

    it 'sets the Content-Type response header if type option is set to a mime type' do
      send_file_app :type => 'application/octet-stream'
      get '/file.txt'
      assert_equal 'application/octet-stream', response['Content-Type']
    end

    it 'sets the Content-Length response header' do
      send_file_app
      get '/file.txt'
      assert_equal 'Hello World'.length.to_s, response['Content-Length']
    end

    it 'sets the Last-Modified response header' do
      send_file_app
      get '/file.txt'
      assert_equal File.mtime(@file).httpdate, response['Last-Modified']
    end

    it 'allows passing in a different Last-Modified response header with :last_modified' do
      time = Time.now
      send_file_app :last_modified => time
      get '/file.txt'
      assert_equal time.httpdate, response['Last-Modified']
    end

    it "returns a 404 when not found" do
      mock_app {
        get('/') { send_file 'this-file-does-not-exist.txt' }
      }
      get '/'
      assert not_found?
    end

    it "does not set the Content-Disposition header by default" do
      send_file_app
      get '/file.txt'
      assert_nil response['Content-Disposition']
    end

    it "sets the Content-Disposition header when :disposition set to 'attachment'" do
      send_file_app :disposition => 'attachment'
      get '/file.txt'
      assert_equal 'attachment; filename="file.txt"', response['Content-Disposition']
    end

    it "does not set add a file name if filename is false" do
      send_file_app :disposition => 'inline', :filename => false
      get '/file.txt'
      assert_equal 'inline', response['Content-Disposition']
    end

    it "sets the Content-Disposition header when :disposition set to 'inline'" do
      send_file_app :disposition => 'inline'
      get '/file.txt'
      assert_equal 'inline; filename="file.txt"', response['Content-Disposition']
    end

    it "sets the Content-Disposition header when :filename provided" do
      send_file_app :filename => 'foo.txt'
      get '/file.txt'
      assert_equal 'attachment; filename="foo.txt"', response['Content-Disposition']
    end

    it 'allows setting a custom status code' do
      send_file_app :status => 201
      get '/file.txt'
      assert_status 201
    end

    it "is able to send files with unknown mime type" do
      @file = File.dirname(__FILE__) + '/file.foobar'
      File.open(@file, 'wb') { |io| io.write('Hello World') }
      send_file_app
      get '/file.txt'
      assert_equal 'application/octet-stream', response['Content-Type']
    end

    it "does not override Content-Type if already set and no explicit type is given" do
      path = @file
      mock_app do
        get('/') do
          content_type :png
          send_file path
        end
      end
      get '/'
      assert_equal 'image/png', response['Content-Type']
    end

    it "does override Content-Type even if already set, if explicit type is given" do
      path = @file
      mock_app do
        get('/') do
          content_type :png
          send_file path, :type => :gif
        end
      end
      get '/'
      assert_equal 'image/gif', response['Content-Type']
    end

    it 'can have :status option as a string' do
      path = @file
      mock_app do
        post '/' do
          send_file path, :status => '422'
        end
      end
      post '/'
      assert_equal response.status, 422
    end
  end

  describe 'cache_control' do
    setup do
      mock_app do
        get('/foo') do
          cache_control :public, :no_cache, :max_age => 60.0
          'Hello World'
        end

        get('/bar') do
          cache_control :public, :no_cache
          'Hello World'
        end
      end
    end

    it 'sets the Cache-Control header' do
      get '/foo'
      assert_equal ['public', 'no-cache', 'max-age=60'], response['Cache-Control'].split(', ')
    end

    it 'last argument does not have to be a hash' do
      get '/bar'
      assert_equal ['public', 'no-cache'], response['Cache-Control'].split(', ')
    end
  end

  describe 'expires' do
    setup do
      mock_app do
        get('/foo') do
          expires 60, :public, :no_cache
          'Hello World'
        end

        get('/bar') { expires Time.now }

        get('/baz') { expires Time.at(0) }

        get('/blah') do
          obj = Object.new
          def obj.method_missing(*a, &b) 60.send(*a, &b) end
          def obj.is_a?(thing) 60.is_a?(thing) end
          expires obj, :public, :no_cache
          'Hello World'
        end

        get('/boom') { expires '9999' }
      end
    end

    it 'sets the Cache-Control header' do
      get '/foo'
      assert_equal ['public', 'no-cache', 'max-age=60'], response['Cache-Control'].split(', ')
    end

    it 'sets the Expires header' do
      get '/foo'
      refute_nil response['Expires']
    end

    it 'allows passing Time.now objects' do
      get '/bar'
      refute_nil response['Expires']
    end

    it 'allows passing Time.at objects' do
      get '/baz'
      assert_equal 'Thu, 01 Jan 1970 00:00:00 GMT', response['Expires']
    end

    it 'accepts values pretending to be a Numeric (like ActiveSupport::Duration)' do
      get '/blah'
      assert_equal ['public', 'no-cache', 'max-age=60'], response['Cache-Control'].split(', ')
    end

    it 'fails when Time.parse raises an ArgumentError' do
      assert_raises(ArgumentError) { get '/boom' }
    end
  end

  describe 'last_modified' do
    it 'ignores nil' do
      mock_app { get('/') { last_modified nil; 200; } }

      get '/'
      assert ! response['Last-Modified']
    end

    it 'does not change a status other than 200' do
      mock_app do
        get('/') do
          status 299
          last_modified Time.at(0)
          'ok'
        end
      end

      get('/', {}, 'HTTP_IF_MODIFIED_SINCE' => 'Sun, 26 Sep 2030 23:43:52 GMT')
      assert_status 299
      assert_body 'ok'
    end

    [Time.now, DateTime.now, Date.today, Time.now.to_i,
      Struct.new(:to_time).new(Time.now) ].each do |last_modified_time|
      describe "with #{last_modified_time.class.name}" do
        setup do
          mock_app do
            get('/') do
              last_modified last_modified_time
              'Boo!'
            end
          end
          wrapper = Object.new.extend Sinatra::Helpers
          @last_modified_time = wrapper.time_for last_modified_time
        end

        # fixes strange missing test error when running complete test suite.
        it("does not complain about missing tests") { }

        context "when there's no If-Modified-Since header" do
          it 'sets the Last-Modified header to a valid RFC 2616 date value' do
            get '/'
            assert_equal @last_modified_time.httpdate, response['Last-Modified']
          end

          it 'conditional GET misses and returns a body' do
            get '/'
            assert_equal 200, status
            assert_equal 'Boo!', body
          end
        end

        context "when there's an invalid If-Modified-Since header" do
          it 'sets the Last-Modified header to a valid RFC 2616 date value' do
            get('/', {}, { 'HTTP_IF_MODIFIED_SINCE' => 'a really weird date' })
            assert_equal @last_modified_time.httpdate, response['Last-Modified']
          end

          it 'conditional GET misses and returns a body' do
            get('/', {}, { 'HTTP_IF_MODIFIED_SINCE' => 'a really weird date' })
            assert_equal 200, status
            assert_equal 'Boo!', body
          end
        end

        context "when the resource has been modified since the If-Modified-Since header date" do
          it 'sets the Last-Modified header to a valid RFC 2616 date value' do
            get('/', {}, { 'HTTP_IF_MODIFIED_SINCE' => (@last_modified_time - 1).httpdate })
            assert_equal @last_modified_time.httpdate, response['Last-Modified']
          end

          it 'conditional GET misses and returns a body' do
            get('/', {}, { 'HTTP_IF_MODIFIED_SINCE' => (@last_modified_time - 1).httpdate })
            assert_equal 200, status
            assert_equal 'Boo!', body
          end

          it 'does not rely on string comparison' do
            mock_app do
              get('/compare') do
                last_modified "Mon, 18 Oct 2010 20:57:11 GMT"
                "foo"
              end
            end

            get('/compare', {}, { 'HTTP_IF_MODIFIED_SINCE' => 'Sun, 26 Sep 2010 23:43:52 GMT' })
            assert_equal 200, status
            assert_equal 'foo', body
            get('/compare', {}, { 'HTTP_IF_MODIFIED_SINCE' => 'Sun, 26 Sep 2030 23:43:52 GMT' })
            assert_equal 304, status
            assert_equal '', body
          end
        end

        context "when the resource has been modified on the exact If-Modified-Since header date" do
          it 'sets the Last-Modified header to a valid RFC 2616 date value' do
            get('/', {}, { 'HTTP_IF_MODIFIED_SINCE' => @last_modified_time.httpdate })
            assert_equal @last_modified_time.httpdate, response['Last-Modified']
          end

          it 'conditional GET matches and halts' do
            get( '/', {}, { 'HTTP_IF_MODIFIED_SINCE' => @last_modified_time.httpdate })
            assert_equal 304, status
            assert_equal '', body
          end
        end

        context "when the resource hasn't been modified since the If-Modified-Since header date" do
          it 'sets the Last-Modified header to a valid RFC 2616 date value' do
            get('/', {}, { 'HTTP_IF_MODIFIED_SINCE' => (@last_modified_time + 1).httpdate })
            assert_equal @last_modified_time.httpdate, response['Last-Modified']
          end

          it 'conditional GET matches and halts' do
            get('/', {}, { 'HTTP_IF_MODIFIED_SINCE' => (@last_modified_time + 1).httpdate })
            assert_equal 304, status
            assert_equal '', body
          end
        end

        context "If-Unmodified-Since" do
          it 'results in 200 if resource has not been modified' do
            get('/', {}, { 'HTTP_IF_UNMODIFIED_SINCE' => 'Sun, 26 Sep 2030 23:43:52 GMT' })
            assert_equal 200, status
            assert_equal 'Boo!', body
          end

          it 'results in 412 if resource has been modified' do
            get('/', {}, { 'HTTP_IF_UNMODIFIED_SINCE' => Time.at(0).httpdate })
            assert_equal 412, status
            assert_equal '', body
          end
        end
      end
    end
  end

  describe 'etag' do
    context "safe requests" do
      it 'returns 200 for normal requests' do
        mock_app do
          get('/') do
            etag 'foo'
            'ok'
          end
        end

        get '/'
        assert_status 200
        assert_body 'ok'
      end

      context "If-None-Match" do
        it 'returns 304 when If-None-Match is *' do
          mock_app do
            get('/') do
              etag 'foo'
              'ok'
            end
          end

          get('/', {}, 'HTTP_IF_NONE_MATCH' => '*')
          assert_status 304
          assert_body ''
        end

        it 'returns 200 when If-None-Match is * for new resources' do
          mock_app do
            get('/') do
              etag 'foo', :new_resource => true
              'ok'
            end
          end

          get('/', {}, 'HTTP_IF_NONE_MATCH' => '*')
          assert_status 200
          assert_body 'ok'
        end

        it 'returns 304 when If-None-Match is * for existing resources' do
          mock_app do
            get('/') do
              etag 'foo', :new_resource => false
              'ok'
            end
          end

          get('/', {}, 'HTTP_IF_NONE_MATCH' => '*')
          assert_status 304
          assert_body ''
        end

        it 'returns 304 when If-None-Match is the etag' do
          mock_app do
            get('/') do
              etag 'foo'
              'ok'
            end
          end

          get('/', {}, 'HTTP_IF_NONE_MATCH' => '"foo"')
          assert_status 304
          assert_body ''
        end

        it 'returns 304 when If-None-Match includes the etag' do
          mock_app do
            get('/') do
              etag 'foo'
              'ok'
            end
          end

          get('/', {}, 'HTTP_IF_NONE_MATCH' => '"bar", "foo"')
          assert_status 304
          assert_body ''
        end

        it 'returns 200 when If-None-Match does not include the etag' do
          mock_app do
            get('/') do
              etag 'foo'
              'ok'
            end
          end

          get('/', {}, 'HTTP_IF_NONE_MATCH' => '"bar"')
          assert_status 200
          assert_body 'ok'
        end

        it 'ignores If-Modified-Since if If-None-Match does not match' do
          mock_app do
            get('/') do
              etag 'foo'
              last_modified Time.at(0)
              'ok'
            end
          end

          get('/', {}, 'HTTP_IF_NONE_MATCH' => '"bar"')
          assert_status 200
          assert_body 'ok'
        end

        it 'does not change a status code other than 2xx or 304' do
          mock_app do
            get('/') do
              status 499
              etag 'foo'
              'ok'
            end
          end

          get('/', {}, 'HTTP_IF_NONE_MATCH' => '"foo"')
          assert_status 499
          assert_body 'ok'
        end

        it 'does change 2xx status codes' do
          mock_app do
            get('/') do
              status 299
              etag 'foo'
              'ok'
            end
          end

          get('/', {}, 'HTTP_IF_NONE_MATCH' => '"foo"')
          assert_status 304
          assert_body ''
        end

        it 'does not send a body on 304 status codes' do
          mock_app do
            get('/') do
              status 304
              etag 'foo'
              'ok'
            end
          end

          get('/', {}, 'HTTP_IF_NONE_MATCH' => '"foo"')
          assert_status 304
          assert_body ''
        end
      end

      context "If-Match" do
        it 'returns 200 when If-Match is the etag' do
          mock_app do
            get('/') do
              etag 'foo'
              'ok'
            end
          end

          get('/', {}, 'HTTP_IF_MATCH' => '"foo"')
          assert_status 200
          assert_body 'ok'
        end

        it 'returns 200 when If-Match includes the etag' do
          mock_app do
            get('/') do
              etag 'foo'
              'ok'
            end
          end

          get('/', {}, 'HTTP_IF_MATCH' => '"foo", "bar"')
          assert_status 200
          assert_body 'ok'
        end

        it 'returns 200 when If-Match is *' do
          mock_app do
            get('/') do
              etag 'foo'
              'ok'
            end
          end

          get('/', {}, 'HTTP_IF_MATCH' => '*')
          assert_status 200
          assert_body 'ok'
        end

        it 'returns 412 when If-Match is * for new resources' do
          mock_app do
            get('/') do
              etag 'foo', :new_resource => true
              'ok'
            end
          end

          get('/', {}, 'HTTP_IF_MATCH' => '*')
          assert_status 412
          assert_body ''
        end

        it 'returns 200 when If-Match is * for existing resources' do
          mock_app do
            get('/') do
              etag 'foo', :new_resource => false
              'ok'
            end
          end

          get('/', {}, 'HTTP_IF_MATCH' => '*')
          assert_status 200
          assert_body 'ok'
        end

        it 'returns 412 when If-Match does not include the etag' do
          mock_app do
            get('/') do
              etag 'foo'
              'ok'
            end
          end

          get('/', {}, 'HTTP_IF_MATCH' => '"bar"')
          assert_status 412
          assert_body ''
        end
      end
    end

    context "idempotent requests" do
      it 'returns 200 for normal requests' do
        mock_app do
          put('/') do
            etag 'foo'
            'ok'
          end
        end

        put '/'
        assert_status 200
        assert_body 'ok'
      end

      context "If-None-Match" do
        it 'returns 412 when If-None-Match is *' do
          mock_app do
            put('/') do
              etag 'foo'
              'ok'
            end
          end

          put('/', {}, 'HTTP_IF_NONE_MATCH' => '*')
          assert_status 412
          assert_body ''
        end

        it 'returns 200 when If-None-Match is * for new resources' do
          mock_app do
            put('/') do
              etag 'foo', :new_resource => true
              'ok'
            end
          end

          put('/', {}, 'HTTP_IF_NONE_MATCH' => '*')
          assert_status 200
          assert_body 'ok'
        end

        it 'returns 412 when If-None-Match is * for existing resources' do
          mock_app do
            put('/') do
              etag 'foo', :new_resource => false
              'ok'
            end
          end

          put('/', {}, 'HTTP_IF_NONE_MATCH' => '*')
          assert_status 412
          assert_body ''
        end

        it 'returns 412 when If-None-Match is the etag' do
          mock_app do
            put '/' do
              etag 'foo'
              'ok'
            end
          end

          put('/', {}, 'HTTP_IF_NONE_MATCH' => '"foo"')
          assert_status 412
          assert_body ''
        end

        it 'returns 412 when If-None-Match includes the etag' do
          mock_app do
            put('/') do
              etag 'foo'
              'ok'
            end
          end

          put('/', {}, 'HTTP_IF_NONE_MATCH' => '"bar", "foo"')
          assert_status 412
          assert_body ''
        end

        it 'returns 200 when If-None-Match does not include the etag' do
          mock_app do
            put('/') do
              etag 'foo'
              'ok'
            end
          end

          put('/', {}, 'HTTP_IF_NONE_MATCH' => '"bar"')
          assert_status 200
          assert_body 'ok'
        end

        it 'ignores If-Modified-Since if If-None-Match does not match' do
          mock_app do
            put('/') do
              etag 'foo'
              last_modified Time.at(0)
              'ok'
            end
          end

          put('/', {}, 'HTTP_IF_NONE_MATCH' => '"bar"')
          assert_status 200
          assert_body 'ok'
        end
      end

      context "If-Match" do
        it 'returns 200 when If-Match is the etag' do
          mock_app do
            put('/') do
              etag 'foo'
              'ok'
            end
          end

          put('/', {}, 'HTTP_IF_MATCH' => '"foo"')
          assert_status 200
          assert_body 'ok'
        end

        it 'returns 200 when If-Match includes the etag' do
          mock_app do
            put('/') do
              etag 'foo'
              'ok'
            end
          end

          put('/', {}, 'HTTP_IF_MATCH' => '"foo", "bar"')
          assert_status 200
          assert_body 'ok'
        end

        it 'returns 200 when If-Match is *' do
          mock_app do
            put('/') do
              etag 'foo'
              'ok'
            end
          end

          put('/', {}, 'HTTP_IF_MATCH' => '*')
          assert_status 200
          assert_body 'ok'
        end

        it 'returns 412 when If-Match is * for new resources' do
          mock_app do
            put('/') do
              etag 'foo', :new_resource => true
              'ok'
            end
          end

          put('/', {}, 'HTTP_IF_MATCH' => '*')
          assert_status 412
          assert_body ''
        end

        it 'returns 200 when If-Match is * for existing resources' do
          mock_app do
            put('/') do
              etag 'foo', :new_resource => false
              'ok'
            end
          end

          put('/', {}, 'HTTP_IF_MATCH' => '*')
          assert_status 200
          assert_body 'ok'
        end

        it 'returns 412 when If-Match does not include the etag' do
          mock_app do
            put('/') do
              etag 'foo'
              'ok'
            end
          end

          put('/', {}, 'HTTP_IF_MATCH' => '"bar"')
          assert_status 412
          assert_body ''
        end
      end
    end

    context "post requests" do
      it 'returns 200 for normal requests' do
        mock_app do
          post('/') do
            etag 'foo'
            'ok'
          end
        end

        post('/')
        assert_status 200
        assert_body 'ok'
      end

      context "If-None-Match" do
        it 'returns 200 when If-None-Match is *' do
          mock_app do
            post('/') do
              etag 'foo'
              'ok'
            end
          end

          post('/', {}, 'HTTP_IF_NONE_MATCH' => '*')
          assert_status 200
          assert_body 'ok'
        end

        it 'returns 200 when If-None-Match is * for new resources' do
          mock_app do
            post('/') do
              etag 'foo', :new_resource => true
              'ok'
            end
          end

          post('/', {}, 'HTTP_IF_NONE_MATCH' => '*')
          assert_status 200
          assert_body 'ok'
        end

        it 'returns 412 when If-None-Match is * for existing resources' do
          mock_app do
            post('/') do
              etag 'foo', :new_resource => false
              'ok'
            end
          end

          post('/', {}, 'HTTP_IF_NONE_MATCH' => '*')
          assert_status 412
          assert_body ''
        end

        it 'returns 412 when If-None-Match is the etag' do
          mock_app do
            post('/') do
              etag 'foo'
              'ok'
            end
          end

          post('/', {}, 'HTTP_IF_NONE_MATCH' => '"foo"')
          assert_status 412
          assert_body ''
        end

        it 'returns 412 when If-None-Match includes the etag' do
          mock_app do
            post('/') do
              etag 'foo'
              'ok'
            end
          end

          post('/', {}, 'HTTP_IF_NONE_MATCH' => '"bar", "foo"')
          assert_status 412
          assert_body ''
        end

        it 'returns 200 when If-None-Match does not include the etag' do
          mock_app do
            post('/') do
              etag 'foo'
              'ok'
            end
          end

          post('/', {}, 'HTTP_IF_NONE_MATCH' => '"bar"')
          assert_status 200
          assert_body 'ok'
        end

        it 'ignores If-Modified-Since if If-None-Match does not match' do
          mock_app do
            post('/') do
              etag 'foo'
              last_modified Time.at(0)
              'ok'
            end
          end

          post('/', {}, 'HTTP_IF_NONE_MATCH' => '"bar"')
          assert_status 200
          assert_body 'ok'
        end
      end

      context "If-Match" do
        it 'returns 200 when If-Match is the etag' do
          mock_app do
            post('/') do
              etag 'foo'
              'ok'
            end
          end

          post('/', {}, 'HTTP_IF_MATCH' => '"foo"')
          assert_status 200
          assert_body 'ok'
        end

        it 'returns 200 when If-Match includes the etag' do
          mock_app do
            post('/') do
              etag 'foo'
              'ok'
            end
          end

          post('/', {}, 'HTTP_IF_MATCH' => '"foo", "bar"')
          assert_status 200
          assert_body 'ok'
        end

        it 'returns 412 when If-Match is *' do
          mock_app do
            post('/') do
              etag 'foo'
              'ok'
            end
          end

          post('/', {}, 'HTTP_IF_MATCH' => '*')
          assert_status 412
          assert_body ''
        end

        it 'returns 412 when If-Match is * for new resources' do
          mock_app do
            post('/') do
              etag 'foo', :new_resource => true
              'ok'
            end
          end

          post('/', {}, 'HTTP_IF_MATCH' => '*')
          assert_status 412
          assert_body ''
        end

        it 'returns 200 when If-Match is * for existing resources' do
          mock_app do
            post('/') do
              etag 'foo', :new_resource => false
              'ok'
            end
          end

          post('/', {}, 'HTTP_IF_MATCH' => '*')
          assert_status 200
          assert_body 'ok'
        end

        it 'returns 412 when If-Match does not include the etag' do
          mock_app do
            post('/') do
              etag 'foo'
              'ok'
            end
          end

          post('/', {}, 'HTTP_IF_MATCH' => '"bar"')
          assert_status 412
          assert_body ''
        end
      end
    end

    it 'uses a weak etag with the :weak option' do
      mock_app do
        get('/') do
          etag 'FOO', :weak
          "that's weak, dude."
        end
      end
      get '/'
      assert_equal 'W/"FOO"', response['ETag']
    end

    it 'raises an ArgumentError for an invalid strength' do
      mock_app do
        get('/') do
          etag 'FOO', :w00t
          "that's weak, dude."
        end
      end
      assert_raises(ArgumentError) { get('/') }
    end
  end

  describe 'back' do
    it "makes redirecting back pretty" do
      mock_app { get('/foo') { redirect back } }

      get('/foo', {}, 'HTTP_REFERER' => 'http://github.com')
      assert redirect?
      assert_equal "http://github.com", response.location
    end
  end

  describe 'uri' do
    it 'generates absolute urls' do
      mock_app { get('/') { uri }}
      get '/'
      assert_equal 'http://example.org/', body
    end

    it 'includes path_info' do
      mock_app { get('/:name') { uri }}
      get '/foo'
      assert_equal 'http://example.org/foo', body
    end

    it 'allows passing an alternative to path_info' do
      mock_app { get('/:name') { uri '/bar' }}
      get '/foo'
      assert_equal 'http://example.org/bar', body
    end

    it 'includes script_name' do
      mock_app { get('/:name') { uri '/bar' }}
      get '/foo', {}, { "SCRIPT_NAME" => '/foo' }
      assert_equal 'http://example.org/foo/bar', body
    end

    it 'handles absolute URIs' do
      mock_app { get('/') { uri 'http://google.com' }}
      get '/'
      assert_equal 'http://google.com', body
    end

    it 'handles different protocols' do
      mock_app { get('/') { uri 'mailto:jsmith@example.com' }}
      get '/'
      assert_equal 'mailto:jsmith@example.com', body
    end

    it 'is aliased to #url' do
      mock_app { get('/') { url }}
      get '/'
      assert_equal 'http://example.org/', body
    end

    it 'is aliased to #to' do
      mock_app { get('/') { to }}
      get '/'
      assert_equal 'http://example.org/', body
    end
  end

  describe 'logger' do
    it 'logging works when logging is enabled' do
      mock_app do
        enable :logging
        get('/') do
          logger.info "Program started"
          logger.warn "Nothing to do!"
        end
      end
      io = StringIO.new
      get '/', {}, 'rack.errors' => io
      assert io.string.include?("INFO -- : Program started")
      assert io.string.include?("WARN -- : Nothing to do")
    end

    it 'logging works when logging is disable, but no output is produced' do
      mock_app do
        disable :logging
        get('/') do
          logger.info "Program started"
          logger.warn "Nothing to do!"
        end
      end
      io = StringIO.new
      get '/', {}, 'rack.errors' => io
      assert !io.string.include?("INFO -- : Program started")
      assert !io.string.include?("WARN -- : Nothing to do")
    end

    it 'does not create a logger when logging is set to nil' do
      mock_app do
        set :logging, nil
        get('/') { logger.inspect }
      end

      get '/'
      assert_body 'nil'
    end
  end

  module ::HelperOne; def one; '1'; end; end
  module ::HelperTwo; def two; '2'; end; end

  describe 'Adding new helpers' do
    it 'takes a list of modules to mix into the app' do
      mock_app do
        helpers ::HelperOne, ::HelperTwo

        get('/one') { one }

        get('/two') { two }
      end

      get '/one'
      assert_equal '1', body

      get '/two'
      assert_equal '2', body
    end

    it 'takes a block to mix into the app' do
      mock_app do
        helpers do
          def foo
            'foo'
          end
        end

        get('/') { foo }
      end

      get '/'
      assert_equal 'foo', body
    end

    it 'evaluates the block in class context so that methods can be aliased' do
      mock_app do
        helpers { alias_method :h, :escape_html }

        get('/') { h('42 < 43') }
      end

      get '/'
      assert ok?
      assert_equal '42 &lt; 43', body
    end
  end
end
