require 'rack/content_length'

describe Rack::ContentLength do
  should "set Content-Length on Array bodies if none is set" do
    app = lambda { |env| [200, {'Content-Type' => 'text/plain'}, ["Hello, World!"]] }
    response = Rack::ContentLength.new(app).call({})
    response[1]['Content-Length'].should.equal '13'
  end

  should "not set Content-Length on variable length bodies" do
    body = lambda { "Hello World!" }
    def body.each ; yield call ; end

    app = lambda { |env| [200, {'Content-Type' => 'text/plain'}, body] }
    response = Rack::ContentLength.new(app).call({})
    response[1]['Content-Length'].should.be.nil
  end

  should "not change Content-Length if it is already set" do
    app = lambda { |env| [200, {'Content-Type' => 'text/plain', 'Content-Length' => '1'}, "Hello, World!"] }
    response = Rack::ContentLength.new(app).call({})
    response[1]['Content-Length'].should.equal '1'
  end

  should "not set Content-Length on 304 responses" do
    app = lambda { |env| [304, {'Content-Type' => 'text/plain'}, []] }
    response = Rack::ContentLength.new(app).call({})
    response[1]['Content-Length'].should.equal nil
  end

  should "not set Content-Length when Transfer-Encoding is chunked" do
    app = lambda { |env| [200, {'Transfer-Encoding' => 'chunked'}, []] }
    response = Rack::ContentLength.new(app).call({})
    response[1]['Content-Length'].should.equal nil
  end

  # Using "Connection: close" for this is fairly contended. It might be useful
  # to have some other way to signal this.
  #
  # should "not force a Content-Length when Connection:close" do
  #   app = lambda { |env| [200, {'Connection' => 'close'}, []] }
  #   response = Rack::ContentLength.new(app).call({})
  #   response[1]['Content-Length'].should.equal nil
  # end

  should "close bodies that need to be closed" do
    body = Struct.new(:body) do
      attr_reader :closed
      def each; body.join; end
      def close; @closed = true; end
      def to_ary; end
    end.new(%w[one two three])

    app = lambda { |env| [200, {}, body] }
    Rack::ContentLength.new(app).call({})
    body.closed.should.equal true
  end

  should "support single-execute bodies" do
    body = Struct.new(:body) do
      def each
        yield body.shift until body.empty?
      end
      def to_ary; end
    end.new(%w[one two three])

    app = lambda { |env| [200, {}, body] }
    response = Rack::ContentLength.new(app).call({})
    expected = %w[one two three]
    response[1]['Content-Length'].should.equal expected.join.size.to_s
    response[2].should.equal expected
  end
end
