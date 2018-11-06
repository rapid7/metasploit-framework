require "spec_helper"

describe Rack::Test::Session do
  describe "initialization" do
    it "supports being initialized with a Rack::MockSession app" do
      session = Rack::Test::Session.new(Rack::MockSession.new(app))
      session.request("/").should be_ok
    end

    it "supports being initialized with an app" do
      session = Rack::Test::Session.new(app)
      session.request("/").should be_ok
    end
  end

  describe "#request" do
    it "requests the URI using GET by default" do
      request "/"
      last_request.should be_get
      last_response.should be_ok
    end

    it "returns a response" do
      request("/").should be_ok
    end

    it "uses the provided env" do
      request "/", "X-Foo" => "bar"
      last_request.env["X-Foo"].should == "bar"
    end

    it "allows HTTP_HOST to be set" do
      request "/", "HTTP_HOST" => "www.example.ua"
      last_request.env['HTTP_HOST'].should == "www.example.ua"
    end

    it "sets HTTP_HOST with port for non-default ports" do
      request "http://foo.com:8080"
      last_request.env["HTTP_HOST"].should == "foo.com:8080"
      request "https://foo.com:8443"
      last_request.env["HTTP_HOST"].should == "foo.com:8443"
    end

    it "sets HTTP_HOST without port for default ports" do
      request "http://foo.com"
      last_request.env["HTTP_HOST"].should == "foo.com"
      request "http://foo.com:80"
      last_request.env["HTTP_HOST"].should == "foo.com"
      request "https://foo.com:443"
      last_request.env["HTTP_HOST"].should == "foo.com"
    end

    it "defaults to GET" do
      request "/"
      last_request.env["REQUEST_METHOD"].should == "GET"
    end

    it "defaults the REMOTE_ADDR to 127.0.0.1" do
      request "/"
      last_request.env["REMOTE_ADDR"].should == "127.0.0.1"
    end

    it "sets rack.test to true in the env" do
      request "/"
      last_request.env["rack.test"].should == true
    end

    it "defaults to port 80" do
      request "/"
      last_request.env["SERVER_PORT"].should == "80"
    end

    it "defaults to example.org" do
      request "/"
      last_request.env["SERVER_NAME"].should == "example.org"
    end

    it "yields the response to a given block" do
      request "/" do |response|
        response.should be_ok
      end
    end

    it "supports sending :params" do
      request "/", :params => { "foo" => "bar" }
      last_request.GET["foo"].should == "bar"
    end

    it "doesn't follow redirects by default" do
      request "/redirect"
      last_response.should be_redirect
      last_response.body.should be_empty
    end

    it "allows passing :input in for POSTs" do
      request "/", :method => :post, :input => "foo"
      last_request.env["rack.input"].read.should == "foo"
    end

    it "converts method names to a uppercase strings" do
      request "/", :method => :put
      last_request.env["REQUEST_METHOD"].should == "PUT"
    end

    it "prepends a slash to the URI path" do
      request "foo"
      last_request.env["PATH_INFO"].should == "/foo"
    end

    it "accepts params and builds query strings for GET requests" do
      request "/foo?baz=2", :params => {:foo => {:bar => "1"}}
      last_request.GET.should == { "baz" => "2", "foo" => { "bar" => "1" }}
    end

    it "parses query strings with repeated variable names correctly" do
      request "/foo?bar=2&bar=3"
      last_request.GET.should == { "bar" => "3" }
    end

    it "accepts raw input in params for GET requests" do
      request "/foo?baz=2", :params => "foo[bar]=1"
      last_request.GET.should == { "baz" => "2", "foo" => { "bar" => "1" }}
    end

    it "does not rewrite a GET query string when :params is not supplied" do
      request "/foo?a=1&b=2&c=3&e=4&d=5+%20"
      last_request.query_string.should == "a=1&b=2&c=3&e=4&d=5+%20"
    end

    it "accepts params and builds url encoded params for POST requests" do
      request "/foo", :method => :post, :params => {:foo => {:bar => "1"}}
      last_request.env["rack.input"].read.should == "foo[bar]=1"
    end

    it "accepts raw input in params for POST requests" do
      request "/foo", :method => :post, :params => "foo[bar]=1"
      last_request.env["rack.input"].read.should == "foo[bar]=1"
    end

    context "when the response body responds_to?(:close)" do
      class CloseableBody
        def initialize
          @closed = false
        end

        def each
          return if @closed
          yield "Hello, World!"
        end

        def close
          @closed = true
        end
      end

      it "closes response's body" do
        body = CloseableBody.new
        body.should_receive(:close)

        app = lambda do |env|
          [200, {"Content-Type" => "text/html", "Content-Length" => "13"}, body]
        end

        session = Rack::Test::Session.new(Rack::MockSession.new(app))
        session.request("/")
      end

      it "closes response's body after iteration" do
        app = lambda do |env|
          [200, {"Content-Type" => "text/html", "Content-Length" => "13"}, CloseableBody.new]
        end

        session = Rack::Test::Session.new(Rack::MockSession.new(app))
        session.request("/")
        session.last_response.body.should == "Hello, World!"
      end
    end

    context "when input is given" do
      it "sends the input" do
        request "/", :method => "POST", :input => "foo"
        last_request.env["rack.input"].read.should == "foo"
      end

      it "does not send a multipart request" do
        request "/", :method => "POST", :input => "foo"
        last_request.env["CONTENT_TYPE"].should_not == "application/x-www-form-urlencoded"
      end
    end

    context "for a POST specified with :method" do
      it "uses application/x-www-form-urlencoded as the CONTENT_TYPE" do
        request "/", :method => "POST"
        last_request.env["CONTENT_TYPE"].should == "application/x-www-form-urlencoded"
      end
    end

    context "for a POST specified with REQUEST_METHOD" do
      it "uses application/x-www-form-urlencoded as the CONTENT_TYPE" do
        request "/", "REQUEST_METHOD" => "POST"
        last_request.env["CONTENT_TYPE"].should == "application/x-www-form-urlencoded"
      end
    end

    context "when CONTENT_TYPE is specified in the env" do
      it "does not overwrite the CONTENT_TYPE" do
        request "/", "CONTENT_TYPE" => "application/xml"
        last_request.env["CONTENT_TYPE"].should == "application/xml"
      end
    end

    context "when the URL is https://" do
      it "sets rack.url_scheme to https" do
        get "https://example.org/"
        last_request.env["rack.url_scheme"].should == "https"
      end

      it "sets SERVER_PORT to 443" do
        get "https://example.org/"
        last_request.env["SERVER_PORT"].should == "443"
      end

      it "sets HTTPS to on" do
        get "https://example.org/"
        last_request.env["HTTPS"].should == "on"
      end
    end

    context "for a XHR" do
      it "sends XMLHttpRequest for the X-Requested-With header" do
        request "/", :xhr => true
        last_request.env["HTTP_X_REQUESTED_WITH"].should == "XMLHttpRequest"
        last_request.should be_xhr
      end
    end
  end

  describe "#header" do
    it "sets a header to be sent with requests" do
      header "User-Agent", "Firefox"
      request "/"

      last_request.env["HTTP_USER_AGENT"].should == "Firefox"
    end

    it "sets a Content-Type to be sent with requests" do
      header "Content-Type", "application/json"
      request "/"

      last_request.env["CONTENT_TYPE"].should == "application/json"
    end

    it "sets a Host to be sent with requests" do
      header "Host", "www.example.ua"
      request "/"

      last_request.env["HTTP_HOST"].should == "www.example.ua"
    end

    it "persists across multiple requests" do
      header "User-Agent", "Firefox"
      request "/"
      request "/"

      last_request.env["HTTP_USER_AGENT"].should == "Firefox"
    end

    it "overwrites previously set headers" do
      header "User-Agent", "Firefox"
      header "User-Agent", "Safari"
      request "/"

      last_request.env["HTTP_USER_AGENT"].should == "Safari"
    end

    it "can be used to clear a header" do
      header "User-Agent", "Firefox"
      header "User-Agent", nil
      request "/"

      last_request.env.should_not have_key("HTTP_USER_AGENT")
    end

    it "is overridden by headers sent during the request" do
      header "User-Agent", "Firefox"
      request "/", "HTTP_USER_AGENT" => "Safari"

      last_request.env["HTTP_USER_AGENT"].should == "Safari"
    end
  end

  describe "#env" do
    it "sets the env to be sent with requests" do
      env "rack.session", {:csrf => 'token'}
      request "/"

      last_request.env["rack.session"].should == {:csrf => 'token'}
    end

    it "persists across multiple requests" do
      env "rack.session", {:csrf => 'token'}
      request "/"
      request "/"

      last_request.env["rack.session"].should == {:csrf => 'token'}
    end

    it "overwrites previously set envs" do
      env "rack.session", {:csrf => 'token'}
      env "rack.session", {:some => :thing}
      request "/"

      last_request.env["rack.session"].should == {:some => :thing}
    end

    it "can be used to clear a env" do
      env "rack.session", {:csrf => 'token'}
      env "rack.session", nil
      request "/"

      last_request.env.should_not have_key("X_CSRF_TOKEN")
    end

    it "is overridden by envs sent during the request" do
      env "rack.session", {:csrf => 'token'}
      request "/", "rack.session" => {:some => :thing}

      last_request.env["rack.session"].should == {:some => :thing}
    end
  end

  describe "#authorize" do
    it "sets the HTTP_AUTHORIZATION header" do
      authorize "bryan", "secret"
      request "/"

      last_request.env["HTTP_AUTHORIZATION"].should == "Basic YnJ5YW46c2VjcmV0\n"
    end

    it "includes the header for subsequent requests" do
      basic_authorize "bryan", "secret"
      request "/"
      request "/"

      last_request.env["HTTP_AUTHORIZATION"].should == "Basic YnJ5YW46c2VjcmV0\n"
    end
  end

  describe "follow_redirect!" do
    it "follows redirects" do
      get "/redirect"
      follow_redirect!

      last_response.should_not be_redirect
      last_response.body.should == "You've been redirected"
      last_request.env["HTTP_REFERER"].should eql("http://example.org/redirect")
    end

    it "does not include params when following the redirect" do
      get "/redirect", { "foo" => "bar" }
      follow_redirect!

      last_request.GET.should == {}
    end

    it "raises an error if the last_response is not set" do
      lambda {
        follow_redirect!
      }.should raise_error(Rack::Test::Error)
    end

    it "raises an error if the last_response is not a redirect" do
      get "/"

      lambda {
        follow_redirect!
      }.should raise_error(Rack::Test::Error)
    end
  end

  describe "#last_request" do
    it "returns the most recent request" do
      request "/"
      last_request.env["PATH_INFO"].should == "/"
    end

    it "raises an error if no requests have been issued" do
      lambda {
        last_request
      }.should raise_error(Rack::Test::Error)
    end
  end

  describe "#last_response" do
    it "returns the most recent response" do
      request "/"
      last_response["Content-Type"].should == "text/html;charset=utf-8"
    end

    it "raises an error if no requests have been issued" do
      lambda {
        last_response
      }.should raise_error
    end
  end

  describe "after_request" do
    it "runs callbacks after each request" do
      ran = false

      rack_mock_session.after_request do
        ran = true
      end

      get "/"
      ran.should == true
    end

    it "runs multiple callbacks" do
      count = 0

      2.times do
        rack_mock_session.after_request do
          count += 1
        end
      end

      get "/"
      count.should == 2
    end
  end

  describe "#get" do
    it_should_behave_like "any #verb methods"

    def verb
      "get"
    end

    it "uses the provided params hash" do
      get "/", :foo => "bar"
      last_request.GET.should == { "foo" => "bar" }
    end

    it "sends params with parens in names" do
      get "/", "foo(1i)" => "bar"
      last_request.GET["foo(1i)"].should == "bar"
    end

    it "supports params with encoding sensitive names" do
      get "/", "foo bar" => "baz"
      last_request.GET["foo bar"].should == "baz"
    end

    it "supports params with nested encoding sensitive names" do
      get "/", "boo" => {"foo bar" => "baz"}
      last_request.GET.should == {"boo" => {"foo bar" => "baz"}}
    end

    it "accepts params in the path" do
      get "/?foo=bar"
      last_request.GET.should == { "foo" => "bar" }
    end
  end

  describe "#head" do
    it_should_behave_like "any #verb methods"

    def verb
      "head"
    end
  end

  describe "#post" do
    it_should_behave_like "any #verb methods"

    def verb
      "post"
    end

    it "uses the provided params hash" do
      post "/", :foo => "bar"
      last_request.POST.should == { "foo" => "bar" }
    end

    it "supports params with encoding sensitive names" do
      post "/", "foo bar" => "baz"
      last_request.POST["foo bar"].should == "baz"
    end

    it "uses application/x-www-form-urlencoded as the CONTENT_TYPE" do
      post "/"
      last_request.env["CONTENT_TYPE"].should == "application/x-www-form-urlencoded"
    end

    it "accepts a body" do
      post "/", "Lobsterlicious!"
      last_request.body.read.should == "Lobsterlicious!"
    end

    context "when CONTENT_TYPE is specified in the env" do
      it "does not overwrite the CONTENT_TYPE" do
        post "/", {}, { "CONTENT_TYPE" => "application/xml" }
        last_request.env["CONTENT_TYPE"].should == "application/xml"
      end
    end
  end

  describe "#put" do
    it_should_behave_like "any #verb methods"

    def verb
      "put"
    end

    it "accepts a body" do
      put "/", "Lobsterlicious!"
      last_request.body.read.should == "Lobsterlicious!"
    end
  end

  describe "#patch" do
    it_should_behave_like "any #verb methods"

    def verb
      "patch"
    end

    it "accepts a body" do
      patch "/", "Lobsterlicious!"
      last_request.body.read.should == "Lobsterlicious!"
    end
  end

  describe "#delete" do
    it_should_behave_like "any #verb methods"

    def verb
      "delete"
    end
  end

  describe "#options" do
    it_should_behave_like "any #verb methods"

    def verb
      "options"
    end
  end
end
