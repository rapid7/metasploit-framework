require 'stringio'
require 'time'  # for Time#httpdate
require 'rack/deflater'
require 'rack/lint'
require 'rack/mock'
require 'zlib'

describe Rack::Deflater do

  def build_response(status, body, accept_encoding, options = {})
    body = [body] if body.respond_to? :to_str
    app = lambda do |env|
      res = [status, options['response_headers'] || {}, body]
      res[1]['Content-Type'] = 'text/plain' unless res[0] == 304
      res
    end

    request = Rack::MockRequest.env_for('', (options['request_headers'] || {}).merge('HTTP_ACCEPT_ENCODING' => accept_encoding))
    deflater = Rack::Lint.new Rack::Deflater.new(app, options['deflater_options'] || {})

    deflater.call(request)
  end

  ##
  # Constructs response object and verifies if it yields right results
  #
  # [expected_status] expected response status, e.g. 200, 304
  # [expected_body] expected response body
  # [accept_encoing] what Accept-Encoding header to send and expect, e.g.
  #                  'deflate' - accepts and expects deflate encoding in response
  #                  { 'gzip' => nil } - accepts gzip but expects no encoding in response
  # [options] hash of request options, i.e.
  #           'app_status' - what status dummy app should return (may be changed by deflater at some point)
  #           'app_body' - what body dummy app should return (may be changed by deflater at some point)
  #           'request_headers' - extra reqest headers to be sent
  #           'response_headers' - extra response headers to be returned
  #           'deflater_options' - options passed to deflater middleware
  # [block] useful for doing some extra verification
  def verify(expected_status, expected_body, accept_encoding, options = {}, &block)
    accept_encoding, expected_encoding = if accept_encoding.kind_of?(Hash)
      [accept_encoding.keys.first, accept_encoding.values.first]
    else
      [accept_encoding, accept_encoding.dup]
    end

    # build response
    status, headers, body = build_response(
      options['app_status'] || expected_status,
      options['app_body'] || expected_body,
      accept_encoding,
      options
    )

    # verify status
    status.should.equal(expected_status)

    # verify body
    unless options['skip_body_verify']
      body_text = ''
      body.each { |part| body_text << part }

      deflated_body = case expected_encoding
      when 'deflate'
        inflater = Zlib::Inflate.new(-Zlib::MAX_WBITS)
        inflater.inflate(body_text) << inflater.finish
      when 'gzip'
        io = StringIO.new(body_text)
        gz = Zlib::GzipReader.new(io)
        tmp = gz.read
        gz.close
        tmp
      else
        body_text
      end

      deflated_body.should.equal(expected_body)
    end

    # yield full response verification
    yield(status, headers, body) if block_given?
  end

  should 'be able to deflate bodies that respond to each' do
    app_body = Object.new
    class << app_body; def each; yield('foo'); yield('bar'); end; end

    verify(200, 'foobar', 'deflate', { 'app_body' => app_body }) do |status, headers, body|
      headers.should.equal({
        'Content-Encoding' => 'deflate',
        'Vary' => 'Accept-Encoding',
        'Content-Type' => 'text/plain'
      })
    end
  end

  should 'flush deflated chunks to the client as they become ready' do
    app_body = Object.new
    class << app_body; def each; yield('foo'); yield('bar'); end; end

    verify(200, app_body, 'deflate', { 'skip_body_verify' => true }) do |status, headers, body|
      headers.should.equal({
        'Content-Encoding' => 'deflate',
        'Vary' => 'Accept-Encoding',
        'Content-Type' => 'text/plain'
      })

      buf = []
      inflater = Zlib::Inflate.new(-Zlib::MAX_WBITS)
      body.each { |part| buf << inflater.inflate(part) }
      buf << inflater.finish

      buf.delete_if { |part| part.empty? }.join.should.equal('foobar')
    end
  end

  # TODO: This is really just a special case of the above...
  should 'be able to deflate String bodies' do
    verify(200, 'Hello world!', 'deflate') do |status, headers, body|
      headers.should.equal({
        'Content-Encoding' => 'deflate',
        'Vary' => 'Accept-Encoding',
        'Content-Type' => 'text/plain'
      })
    end
  end

  should 'be able to gzip bodies that respond to each' do
    app_body = Object.new
    class << app_body; def each; yield('foo'); yield('bar'); end; end

    verify(200, 'foobar', 'gzip', { 'app_body' => app_body }) do |status, headers, body|
      headers.should.equal({
        'Content-Encoding' => 'gzip',
        'Vary' => 'Accept-Encoding',
        'Content-Type' => 'text/plain'
      })
    end
  end

  should 'flush gzipped chunks to the client as they become ready' do
    app_body = Object.new
    class << app_body; def each; yield('foo'); yield('bar'); end; end

    verify(200, app_body, 'gzip', { 'skip_body_verify' => true }) do |status, headers, body|
      headers.should.equal({
        'Content-Encoding' => 'gzip',
        'Vary' => 'Accept-Encoding',
        'Content-Type' => 'text/plain'
      })

      buf = []
      inflater = Zlib::Inflate.new(Zlib::MAX_WBITS + 32)
      body.each { |part| buf << inflater.inflate(part) }
      buf << inflater.finish

      buf.delete_if { |part| part.empty? }.join.should.equal('foobar')
    end
  end

  should 'be able to fallback to no deflation' do
    verify(200, 'Hello world!', 'superzip') do |status, headers, body|
      headers.should.equal({
        'Vary' => 'Accept-Encoding',
        'Content-Type' => 'text/plain'
      })
    end
  end

  should 'be able to skip when there is no response entity body' do
    verify(304, '', { 'gzip' => nil }, { 'app_body' => [] }) do |status, headers, body|
      headers.should.equal({})
    end
  end

  should 'handle the lack of an acceptable encoding' do
    app_body = 'Hello world!'
    not_found_body1 = 'An acceptable encoding for the requested resource / could not be found.'
    not_found_body2 = 'An acceptable encoding for the requested resource /foo/bar could not be found.'
    options1 = {
      'app_status' => 200,
      'app_body' => app_body,
      'request_headers' => {
        'PATH_INFO' => '/'
      }
    }
    options2 = {
      'app_status' => 200,
      'app_body' => app_body,
      'request_headers' => {
        'PATH_INFO' => '/foo/bar'
      }
    }

    verify(406, not_found_body1, 'identity;q=0', options1) do |status, headers, body|
      headers.should.equal({
        'Content-Type' => 'text/plain',
        'Content-Length' => not_found_body1.length.to_s
      })
    end

    verify(406, not_found_body2, 'identity;q=0', options2) do |status, headers, body|
      headers.should.equal({
        'Content-Type' => 'text/plain',
        'Content-Length' => not_found_body2.length.to_s
      })
    end
  end

  should 'handle gzip response with Last-Modified header' do
    last_modified = Time.now.httpdate
    options = {
      'response_headers' => {
        'Content-Type' => 'text/plain',
        'Last-Modified' => last_modified
      }
    }

    verify(200, 'Hello World!', 'gzip', options) do |status, headers, body|
      headers.should.equal({
        'Content-Encoding' => 'gzip',
        'Vary' => 'Accept-Encoding',
        'Last-Modified' => last_modified,
        'Content-Type' => 'text/plain'
      })
    end
  end

  should 'do nothing when no-transform Cache-Control directive present' do
    options = {
      'response_headers' => {
        'Content-Type' => 'text/plain',
        'Cache-Control' => 'no-transform'
      }
    }
    verify(200, 'Hello World!', { 'gzip' => nil }, options) do |status, headers, body|
      headers.should.not.include 'Content-Encoding'
    end
  end

  should 'do nothing when Content-Encoding already present' do
    options = {
      'response_headers' => {
        'Content-Type' => 'text/plain',
        'Content-Encoding' => 'gzip'
      }
    }
    verify(200, 'Hello World!', { 'gzip' => nil }, options)
  end

  should 'deflate when Content-Encoding is identity' do
    options = {
      'response_headers' => {
        'Content-Type' => 'text/plain',
        'Content-Encoding' => 'identity'
      }
    }
    verify(200, 'Hello World!', 'deflate', options)
  end

  should "deflate if content-type matches :include" do
    options = {
      'response_headers' => {
        'Content-Type' => 'text/plain'
      },
      'deflater_options' => {
        :include => %w(text/plain)
      }
    }
    verify(200, 'Hello World!', 'gzip', options)
  end

  should "deflate if content-type is included it :include" do
    options = {
      'response_headers' => {
        'Content-Type' => 'text/plain; charset=us-ascii'
      },
      'deflater_options' => {
        :include => %w(text/plain)
      }
    }
    verify(200, 'Hello World!', 'gzip', options)
  end

  should "not deflate if content-type is not set but given in :include" do
    options = {
      'deflater_options' => {
        :include => %w(text/plain)
      }
    }
    verify(304, 'Hello World!', { 'gzip' => nil }, options)
  end

  should "not deflate if content-type do not match :include" do
    options = {
      'response_headers' => {
        'Content-Type' => 'text/plain'
      },
      'deflater_options' => {
        :include => %w(text/json)
      }
    }
    verify(200, 'Hello World!', { 'gzip' => nil }, options)
  end

  should "deflate response if :if lambda evaluates to true" do
    options = {
      'deflater_options' => {
        :if => lambda { |env, status, headers, body| true }
      }
    }
    verify(200, 'Hello World!', 'deflate', options)
  end

  should "not deflate if :if lambda evaluates to false" do
    options = {
      'deflater_options' => {
        :if => lambda { |env, status, headers, body| false }
      }
    }
    verify(200, 'Hello World!', { 'gzip' => nil }, options)
  end

  should "check for Content-Length via :if" do
    body = 'Hello World!'
    body_len = body.length
    options = {
      'response_headers' => {
        'Content-Length' => body_len.to_s
      },
      'deflater_options' => {
        :if => lambda { |env, status, headers, body|
          headers['Content-Length'].to_i >= body_len
        }
      }
    }

    verify(200, body, 'gzip', options)
  end
end
