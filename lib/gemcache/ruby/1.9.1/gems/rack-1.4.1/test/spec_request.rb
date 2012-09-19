require 'stringio'
require 'cgi'
require 'rack/request'
require 'rack/mock'

describe Rack::Request do
  should "wrap the rack variables" do
    req = Rack::Request.new(Rack::MockRequest.env_for("http://example.com:8080/"))

    req.body.should.respond_to? :gets
    req.scheme.should.equal "http"
    req.request_method.should.equal "GET"

    req.should.be.get
    req.should.not.be.post
    req.should.not.be.put
    req.should.not.be.delete
    req.should.not.be.head
    req.should.not.be.patch

    req.script_name.should.equal ""
    req.path_info.should.equal "/"
    req.query_string.should.equal ""

    req.host.should.equal "example.com"
    req.port.should.equal 8080

    req.content_length.should.equal "0"
    req.content_type.should.be.nil
  end

  should "figure out the correct host" do
    req = Rack::Request.new \
      Rack::MockRequest.env_for("/", "HTTP_HOST" => "www2.example.org")
    req.host.should.equal "www2.example.org"

    req = Rack::Request.new \
      Rack::MockRequest.env_for("/", "SERVER_NAME" => "example.org", "SERVER_PORT" => "9292")
    req.host.should.equal "example.org"

    req = Rack::Request.new \
      Rack::MockRequest.env_for("/", "HTTP_HOST" => "localhost:81", "HTTP_X_FORWARDED_HOST" => "example.org:9292")
    req.host.should.equal "example.org"

    env = Rack::MockRequest.env_for("/", "SERVER_ADDR" => "192.168.1.1", "SERVER_PORT" => "9292")
    env.delete("SERVER_NAME")
    req = Rack::Request.new(env)
    req.host.should.equal "192.168.1.1"

    env = Rack::MockRequest.env_for("/")
    env.delete("SERVER_NAME")
    req = Rack::Request.new(env)
    req.host.should.equal ""
  end

  should "figure out the correct port" do
    req = Rack::Request.new \
      Rack::MockRequest.env_for("/", "HTTP_HOST" => "www2.example.org")
    req.port.should.equal 80

    req = Rack::Request.new \
      Rack::MockRequest.env_for("/", "HTTP_HOST" => "www2.example.org:81")
    req.port.should.equal 81

    req = Rack::Request.new \
      Rack::MockRequest.env_for("/", "SERVER_NAME" => "example.org", "SERVER_PORT" => "9292")
    req.port.should.equal 9292

    req = Rack::Request.new \
      Rack::MockRequest.env_for("/", "HTTP_HOST" => "localhost:81", "HTTP_X_FORWARDED_HOST" => "example.org:9292")
    req.port.should.equal 9292

    req = Rack::Request.new \
      Rack::MockRequest.env_for("/", "HTTP_HOST" => "localhost:81", "HTTP_X_FORWARDED_HOST" => "example.org")
    req.port.should.equal 80

    req = Rack::Request.new \
      Rack::MockRequest.env_for("/", "HTTP_HOST" => "localhost:81", "HTTP_X_FORWARDED_HOST" => "example.org", "HTTP_X_FORWARDED_SSL" => "on")
    req.port.should.equal 443

     req = Rack::Request.new \
      Rack::MockRequest.env_for("/", "HTTP_HOST" => "localhost:81", "HTTP_X_FORWARDED_HOST" => "example.org", "HTTP_X_FORWARDED_PROTO" => "https")
    req.port.should.equal 443

    req = Rack::Request.new \
      Rack::MockRequest.env_for("/", "HTTP_HOST" => "localhost:81", "HTTP_X_FORWARDED_HOST" => "example.org", "HTTP_X_FORWARDED_PORT" => "9393")
    req.port.should.equal 9393

    req = Rack::Request.new \
      Rack::MockRequest.env_for("/", "HTTP_HOST" => "localhost:81", "HTTP_X_FORWARDED_HOST" => "example.org:9393", "SERVER_PORT" => "80")
    req.port.should.equal 9393

    req = Rack::Request.new \
      Rack::MockRequest.env_for("/", "HTTP_HOST" => "localhost:81", "HTTP_X_FORWARDED_HOST" => "example.org", "SERVER_PORT" => "9393")
    req.port.should.equal 80
  end

  should "figure out the correct host with port" do
    req = Rack::Request.new \
      Rack::MockRequest.env_for("/", "HTTP_HOST" => "www2.example.org")
    req.host_with_port.should.equal "www2.example.org"

    req = Rack::Request.new \
      Rack::MockRequest.env_for("/", "HTTP_HOST" => "localhost:81")
    req.host_with_port.should.equal "localhost:81"

    req = Rack::Request.new \
      Rack::MockRequest.env_for("/", "SERVER_NAME" => "example.org", "SERVER_PORT" => "9292")
    req.host_with_port.should.equal "example.org:9292"

    req = Rack::Request.new \
      Rack::MockRequest.env_for("/", "HTTP_HOST" => "localhost:81", "HTTP_X_FORWARDED_HOST" => "example.org:9292")
    req.host_with_port.should.equal "example.org:9292"

    req = Rack::Request.new \
      Rack::MockRequest.env_for("/", "HTTP_HOST" => "localhost:81", "HTTP_X_FORWARDED_HOST" => "example.org", "SERVER_PORT" => "9393")
    req.host_with_port.should.equal "example.org"
  end

  should "parse the query string" do
    req = Rack::Request.new(Rack::MockRequest.env_for("/?foo=bar&quux=bla"))
    req.query_string.should.equal "foo=bar&quux=bla"
    req.GET.should.equal "foo" => "bar", "quux" => "bla"
    req.POST.should.be.empty
    req.params.should.equal "foo" => "bar", "quux" => "bla"
  end

  should "limit the keys from the GET query string" do
    env = Rack::MockRequest.env_for("/?foo=bar")

    old, Rack::Utils.key_space_limit = Rack::Utils.key_space_limit, 1
    begin
      req = Rack::Request.new(env)
      lambda { req.GET }.should.raise(RangeError)
    ensure
      Rack::Utils.key_space_limit = old
    end
  end

  should "limit the key size per nested params hash" do
    nested_query = Rack::MockRequest.env_for("/?foo[bar][baz][qux]=1")
    plain_query  = Rack::MockRequest.env_for("/?foo_bar__baz__qux_=1")

    old, Rack::Utils.key_space_limit = Rack::Utils.key_space_limit, 3
    begin
      lambda { Rack::Request.new(nested_query).GET }.should.not.raise(RangeError)
      lambda { Rack::Request.new(plain_query).GET  }.should.raise(RangeError)
    ensure
      Rack::Utils.key_space_limit = old
    end
  end

  should "not unify GET and POST when calling params" do
    mr = Rack::MockRequest.env_for("/?foo=quux",
      "REQUEST_METHOD" => 'POST',
      :input => "foo=bar&quux=bla"
    )
    req = Rack::Request.new mr

    req.params

    req.GET.should.equal "foo" => "quux"
    req.POST.should.equal "foo" => "bar", "quux" => "bla"
    req.params.should.equal req.GET.merge(req.POST)
  end

  should "raise if rack.input is missing" do
    req = Rack::Request.new({})
    lambda { req.POST }.should.raise(RuntimeError)
  end

  should "parse POST data when method is POST and no Content-Type given" do
    req = Rack::Request.new \
      Rack::MockRequest.env_for("/?foo=quux",
        "REQUEST_METHOD" => 'POST',
        :input => "foo=bar&quux=bla")
    req.content_type.should.be.nil
    req.media_type.should.be.nil
    req.query_string.should.equal "foo=quux"
    req.GET.should.equal "foo" => "quux"
    req.POST.should.equal "foo" => "bar", "quux" => "bla"
    req.params.should.equal "foo" => "bar", "quux" => "bla"
  end

  should "limit the keys from the POST form data" do
    env = Rack::MockRequest.env_for("",
            "REQUEST_METHOD" => 'POST',
            :input => "foo=bar&quux=bla")

    old, Rack::Utils.key_space_limit = Rack::Utils.key_space_limit, 1
    begin
      req = Rack::Request.new(env)
      lambda { req.POST }.should.raise(RangeError)
    ensure
      Rack::Utils.key_space_limit = old
    end
  end

  should "parse POST data with explicit content type regardless of method" do
    req = Rack::Request.new \
      Rack::MockRequest.env_for("/",
        "CONTENT_TYPE" => 'application/x-www-form-urlencoded;foo=bar',
        :input => "foo=bar&quux=bla")
    req.content_type.should.equal 'application/x-www-form-urlencoded;foo=bar'
    req.media_type.should.equal 'application/x-www-form-urlencoded'
    req.media_type_params['foo'].should.equal 'bar'
    req.POST.should.equal "foo" => "bar", "quux" => "bla"
    req.params.should.equal "foo" => "bar", "quux" => "bla"
  end

  should "not parse POST data when media type is not form-data" do
    req = Rack::Request.new \
      Rack::MockRequest.env_for("/?foo=quux",
        "REQUEST_METHOD" => 'POST',
        "CONTENT_TYPE" => 'text/plain;charset=utf-8',
        :input => "foo=bar&quux=bla")
    req.content_type.should.equal 'text/plain;charset=utf-8'
    req.media_type.should.equal 'text/plain'
    req.media_type_params['charset'].should.equal 'utf-8'
    req.POST.should.be.empty
    req.params.should.equal "foo" => "quux"
    req.body.read.should.equal "foo=bar&quux=bla"
  end

  should "parse POST data on PUT when media type is form-data" do
    req = Rack::Request.new \
      Rack::MockRequest.env_for("/?foo=quux",
        "REQUEST_METHOD" => 'PUT',
        "CONTENT_TYPE" => 'application/x-www-form-urlencoded',
        :input => "foo=bar&quux=bla")
    req.POST.should.equal "foo" => "bar", "quux" => "bla"
    req.body.read.should.equal "foo=bar&quux=bla"
  end

  should "rewind input after parsing POST data" do
    input = StringIO.new("foo=bar&quux=bla")
    req = Rack::Request.new \
      Rack::MockRequest.env_for("/",
        "CONTENT_TYPE" => 'application/x-www-form-urlencoded;foo=bar',
        :input => input)
    req.params.should.equal "foo" => "bar", "quux" => "bla"
    input.read.should.equal "foo=bar&quux=bla"
  end

  should "clean up Safari's ajax POST body" do
    req = Rack::Request.new \
      Rack::MockRequest.env_for("/",
        'REQUEST_METHOD' => 'POST', :input => "foo=bar&quux=bla\0")
    req.POST.should.equal "foo" => "bar", "quux" => "bla"
  end

  should "get value by key from params with #[]" do
    req = Rack::Request.new \
      Rack::MockRequest.env_for("?foo=quux")
    req['foo'].should.equal 'quux'
    req[:foo].should.equal 'quux'
  end

  should "set value to key on params with #[]=" do
    req = Rack::Request.new \
      Rack::MockRequest.env_for("?foo=duh")
    req['foo'].should.equal 'duh'
    req[:foo].should.equal 'duh'
    req.params.should.equal 'foo' => 'duh'

    req['foo'] = 'bar'
    req.params.should.equal 'foo' => 'bar'
    req['foo'].should.equal 'bar'
    req[:foo].should.equal 'bar'

    req[:foo] = 'jaz'
    req.params.should.equal 'foo' => 'jaz'
    req['foo'].should.equal 'jaz'
    req[:foo].should.equal 'jaz'
  end

  should "return values for the keys in the order given from values_at" do
    req = Rack::Request.new \
      Rack::MockRequest.env_for("?foo=baz&wun=der&bar=ful")
    req.values_at('foo').should.equal ['baz']
    req.values_at('foo', 'wun').should.equal ['baz', 'der']
    req.values_at('bar', 'foo', 'wun').should.equal ['ful', 'baz', 'der']
  end

  should "extract referrer correctly" do
    req = Rack::Request.new \
      Rack::MockRequest.env_for("/", "HTTP_REFERER" => "/some/path")
    req.referer.should.equal "/some/path"

    req = Rack::Request.new \
      Rack::MockRequest.env_for("/")
    req.referer.should.equal nil
  end

  should "extract user agent correctly" do
    req = Rack::Request.new \
      Rack::MockRequest.env_for("/", "HTTP_USER_AGENT" => "Mozilla/4.0 (compatible)")
    req.user_agent.should.equal "Mozilla/4.0 (compatible)"

    req = Rack::Request.new \
      Rack::MockRequest.env_for("/")
    req.user_agent.should.equal nil
  end

  should "treat missing content type as nil" do
    req = Rack::Request.new \
      Rack::MockRequest.env_for("/")
    req.content_type.should.equal nil
  end

  should "treat empty content type as nil" do
    req = Rack::Request.new \
      Rack::MockRequest.env_for("/", "CONTENT_TYPE" => "")
    req.content_type.should.equal nil
  end

  should "return nil media type for empty content type" do
    req = Rack::Request.new \
      Rack::MockRequest.env_for("/", "CONTENT_TYPE" => "")
    req.media_type.should.equal nil
  end

  should "cache, but invalidates the cache" do
    req = Rack::Request.new \
      Rack::MockRequest.env_for("/?foo=quux",
        "CONTENT_TYPE" => "application/x-www-form-urlencoded",
        :input => "foo=bar&quux=bla")
    req.GET.should.equal "foo" => "quux"
    req.GET.should.equal "foo" => "quux"
    req.env["QUERY_STRING"] = "bla=foo"
    req.GET.should.equal "bla" => "foo"
    req.GET.should.equal "bla" => "foo"

    req.POST.should.equal "foo" => "bar", "quux" => "bla"
    req.POST.should.equal "foo" => "bar", "quux" => "bla"
    req.env["rack.input"] = StringIO.new("foo=bla&quux=bar")
    req.POST.should.equal "foo" => "bla", "quux" => "bar"
    req.POST.should.equal "foo" => "bla", "quux" => "bar"
  end

  should "figure out if called via XHR" do
    req = Rack::Request.new(Rack::MockRequest.env_for(""))
    req.should.not.be.xhr

    req = Rack::Request.new \
      Rack::MockRequest.env_for("", "HTTP_X_REQUESTED_WITH" => "XMLHttpRequest")
    req.should.be.xhr
  end

  should "ssl detection" do
    request = Rack::Request.new(Rack::MockRequest.env_for("/"))
    request.scheme.should.equal "http"
    request.should.not.be.ssl?

    request = Rack::Request.new(Rack::MockRequest.env_for("/", 'HTTPS' => 'on'))
    request.scheme.should.equal "https"
    request.should.be.ssl?

    request = Rack::Request.new(Rack::MockRequest.env_for("/", 'rack.url_scheme' => 'https'))
    request.scheme.should.equal "https"
    request.should.be.ssl?

    request = Rack::Request.new(Rack::MockRequest.env_for("/", 'HTTP_HOST' => 'www.example.org:8080'))
    request.scheme.should.equal "http"
    request.should.not.be.ssl?

    request = Rack::Request.new(Rack::MockRequest.env_for("/", 'HTTP_HOST' => 'www.example.org:8443', 'HTTPS' => 'on'))
    request.scheme.should.equal "https"
    request.should.be.ssl?

    request = Rack::Request.new(Rack::MockRequest.env_for("/", 'HTTP_HOST' => 'www.example.org:8443', 'HTTP_X_FORWARDED_SSL' => 'on'))
    request.scheme.should.equal "https"
    request.should.be.ssl?

    request = Rack::Request.new(Rack::MockRequest.env_for("/", 'HTTP_X_FORWARDED_SCHEME' => 'https'))
    request.scheme.should.equal "https"
    request.should.be.ssl?

    request = Rack::Request.new(Rack::MockRequest.env_for("/", 'HTTP_X_FORWARDED_PROTO' => 'https'))
    request.scheme.should.equal "https"
    request.should.be.ssl?

    request = Rack::Request.new(Rack::MockRequest.env_for("/", 'HTTP_X_FORWARDED_PROTO' => 'https, http, http'))
    request.scheme.should.equal "https"
    request.should.be.ssl?
  end

  should "parse cookies" do
    req = Rack::Request.new \
      Rack::MockRequest.env_for("", "HTTP_COOKIE" => "foo=bar;quux=h&m")
    req.cookies.should.equal "foo" => "bar", "quux" => "h&m"
    req.cookies.should.equal "foo" => "bar", "quux" => "h&m"
    req.env.delete("HTTP_COOKIE")
    req.cookies.should.equal({})
  end

  should "always return the same hash object" do
    req = Rack::Request.new \
      Rack::MockRequest.env_for("", "HTTP_COOKIE" => "foo=bar;quux=h&m")
    hash = req.cookies
    req.env.delete("HTTP_COOKIE")
    req.cookies.should.equal(hash)
    req.env["HTTP_COOKIE"] = "zoo=m"
    req.cookies.should.equal(hash)
  end

  should "modify the cookies hash in place" do
    req = Rack::Request.new(Rack::MockRequest.env_for(""))
    req.cookies.should.equal({})
    req.cookies['foo'] = 'bar'
    req.cookies.should.equal 'foo' => 'bar'
  end

  should "raise any errors on every request" do
    req = Rack::Request.new Rack::MockRequest.env_for("", "HTTP_COOKIE" => "foo=%")
    2.times { proc { req.cookies }.should.raise(ArgumentError) }
  end

  should "parse cookies according to RFC 2109" do
    req = Rack::Request.new \
      Rack::MockRequest.env_for('', 'HTTP_COOKIE' => 'foo=bar;foo=car')
    req.cookies.should.equal 'foo' => 'bar'
  end

  should 'parse cookies with quotes' do
    req = Rack::Request.new Rack::MockRequest.env_for('', {
      'HTTP_COOKIE' => '$Version="1"; Customer="WILE_E_COYOTE"; $Path="/acme"; Part_Number="Rocket_Launcher_0001"; $Path="/acme"'
    })
    req.cookies.should.equal({
      '$Version'    => '"1"',
      'Customer'    => '"WILE_E_COYOTE"',
      '$Path'       => '"/acme"',
      'Part_Number' => '"Rocket_Launcher_0001"',
    })
  end

  should "provide setters" do
    req = Rack::Request.new(e=Rack::MockRequest.env_for(""))
    req.script_name.should.equal ""
    req.script_name = "/foo"
    req.script_name.should.equal "/foo"
    e["SCRIPT_NAME"].should.equal "/foo"

    req.path_info.should.equal "/"
    req.path_info = "/foo"
    req.path_info.should.equal "/foo"
    e["PATH_INFO"].should.equal "/foo"
  end

  should "provide the original env" do
    req = Rack::Request.new(e = Rack::MockRequest.env_for(""))
    req.env.should == e
  end

  should "restore the base URL" do
    Rack::Request.new(Rack::MockRequest.env_for("")).base_url.
      should.equal "http://example.org"
    Rack::Request.new(Rack::MockRequest.env_for("", "SCRIPT_NAME" => "/foo")).base_url.
      should.equal "http://example.org"
  end

  should "restore the URL" do
    Rack::Request.new(Rack::MockRequest.env_for("")).url.
      should.equal "http://example.org/"
    Rack::Request.new(Rack::MockRequest.env_for("", "SCRIPT_NAME" => "/foo")).url.
      should.equal "http://example.org/foo/"
    Rack::Request.new(Rack::MockRequest.env_for("/foo")).url.
      should.equal "http://example.org/foo"
    Rack::Request.new(Rack::MockRequest.env_for("?foo")).url.
      should.equal "http://example.org/?foo"
    Rack::Request.new(Rack::MockRequest.env_for("http://example.org:8080/")).url.
      should.equal "http://example.org:8080/"
    Rack::Request.new(Rack::MockRequest.env_for("https://example.org/")).url.
      should.equal "https://example.org/"

    Rack::Request.new(Rack::MockRequest.env_for("https://example.com:8080/foo?foo")).url.
      should.equal "https://example.com:8080/foo?foo"
  end

  should "restore the full path" do
    Rack::Request.new(Rack::MockRequest.env_for("")).fullpath.
      should.equal "/"
    Rack::Request.new(Rack::MockRequest.env_for("", "SCRIPT_NAME" => "/foo")).fullpath.
      should.equal "/foo/"
    Rack::Request.new(Rack::MockRequest.env_for("/foo")).fullpath.
      should.equal "/foo"
    Rack::Request.new(Rack::MockRequest.env_for("?foo")).fullpath.
      should.equal "/?foo"
    Rack::Request.new(Rack::MockRequest.env_for("http://example.org:8080/")).fullpath.
      should.equal "/"
    Rack::Request.new(Rack::MockRequest.env_for("https://example.org/")).fullpath.
      should.equal "/"

    Rack::Request.new(Rack::MockRequest.env_for("https://example.com:8080/foo?foo")).fullpath.
      should.equal "/foo?foo"
  end

  should "handle multiple media type parameters" do
    req = Rack::Request.new \
      Rack::MockRequest.env_for("/",
        "CONTENT_TYPE" => 'text/plain; foo=BAR,baz=bizzle dizzle;BLING=bam')
      req.should.not.be.form_data
      req.media_type_params.should.include 'foo'
      req.media_type_params['foo'].should.equal 'BAR'
      req.media_type_params.should.include 'baz'
      req.media_type_params['baz'].should.equal 'bizzle dizzle'
      req.media_type_params.should.not.include 'BLING'
      req.media_type_params.should.include 'bling'
      req.media_type_params['bling'].should.equal 'bam'
  end

  should "parse with junk before boundry" do
    # Adapted from RFC 1867.
    input = <<EOF
blah blah\r
\r
--AaB03x\r
content-disposition: form-data; name="reply"\r
\r
yes\r
--AaB03x\r
content-disposition: form-data; name="fileupload"; filename="dj.jpg"\r
Content-Type: image/jpeg\r
Content-Transfer-Encoding: base64\r
\r
/9j/4AAQSkZJRgABAQAAAQABAAD//gA+Q1JFQVRPUjogZ2QtanBlZyB2MS4wICh1c2luZyBJSkcg\r
--AaB03x--\r
EOF
    req = Rack::Request.new Rack::MockRequest.env_for("/",
                      "CONTENT_TYPE" => "multipart/form-data, boundary=AaB03x",
                      "CONTENT_LENGTH" => input.size,
                      :input => input)

    req.POST.should.include "fileupload"
    req.POST.should.include "reply"

    req.should.be.form_data
    req.content_length.should.equal input.size
    req.media_type.should.equal 'multipart/form-data'
    req.media_type_params.should.include 'boundary'
    req.media_type_params['boundary'].should.equal 'AaB03x'

    req.POST["reply"].should.equal "yes"

    f = req.POST["fileupload"]
    f.should.be.kind_of Hash
    f[:type].should.equal "image/jpeg"
    f[:filename].should.equal "dj.jpg"
    f.should.include :tempfile
    f[:tempfile].size.should.equal 76
  end

  should "not infinite loop with a malformed HTTP request" do
    # Adapted from RFC 1867.
    input = <<EOF
--AaB03x
content-disposition: form-data; name="reply"

yes
--AaB03x
content-disposition: form-data; name="fileupload"; filename="dj.jpg"
Content-Type: image/jpeg
Content-Transfer-Encoding: base64

/9j/4AAQSkZJRgABAQAAAQABAAD//gA+Q1JFQVRPUjogZ2QtanBlZyB2MS4wICh1c2luZyBJSkcg
--AaB03x--
EOF
    req = Rack::Request.new Rack::MockRequest.env_for("/",
                      "CONTENT_TYPE" => "multipart/form-data, boundary=AaB03x",
                      "CONTENT_LENGTH" => input.size,
                      :input => input)

    lambda{req.POST}.should.raise(EOFError)
  end


  should "parse multipart form data" do
    # Adapted from RFC 1867.
    input = <<EOF
--AaB03x\r
content-disposition: form-data; name="reply"\r
\r
yes\r
--AaB03x\r
content-disposition: form-data; name="fileupload"; filename="dj.jpg"\r
Content-Type: image/jpeg\r
Content-Transfer-Encoding: base64\r
\r
/9j/4AAQSkZJRgABAQAAAQABAAD//gA+Q1JFQVRPUjogZ2QtanBlZyB2MS4wICh1c2luZyBJSkcg\r
--AaB03x--\r
EOF
    req = Rack::Request.new Rack::MockRequest.env_for("/",
                      "CONTENT_TYPE" => "multipart/form-data, boundary=AaB03x",
                      "CONTENT_LENGTH" => input.size,
                      :input => input)

    req.POST.should.include "fileupload"
    req.POST.should.include "reply"

    req.should.be.form_data
    req.content_length.should.equal input.size
    req.media_type.should.equal 'multipart/form-data'
    req.media_type_params.should.include 'boundary'
    req.media_type_params['boundary'].should.equal 'AaB03x'

    req.POST["reply"].should.equal "yes"

    f = req.POST["fileupload"]
    f.should.be.kind_of Hash
    f[:type].should.equal "image/jpeg"
    f[:filename].should.equal "dj.jpg"
    f.should.include :tempfile
    f[:tempfile].size.should.equal 76
  end

  should "parse big multipart form data" do
    input = <<EOF
--AaB03x\r
content-disposition: form-data; name="huge"; filename="huge"\r
\r
#{"x"*32768}\r
--AaB03x\r
content-disposition: form-data; name="mean"; filename="mean"\r
\r
--AaB03xha\r
--AaB03x--\r
EOF
    req = Rack::Request.new Rack::MockRequest.env_for("/",
                      "CONTENT_TYPE" => "multipart/form-data, boundary=AaB03x",
                      "CONTENT_LENGTH" => input.size,
                      :input => input)

    req.POST["huge"][:tempfile].size.should.equal 32768
    req.POST["mean"][:tempfile].size.should.equal 10
    req.POST["mean"][:tempfile].read.should.equal "--AaB03xha"
  end

  should "detect invalid multipart form data" do
    input = <<EOF
--AaB03x\r
content-disposition: form-data; name="huge"; filename="huge"\r
EOF
    req = Rack::Request.new Rack::MockRequest.env_for("/",
                      "CONTENT_TYPE" => "multipart/form-data, boundary=AaB03x",
                      "CONTENT_LENGTH" => input.size,
                      :input => input)

    lambda { req.POST }.should.raise(EOFError)

    input = <<EOF
--AaB03x\r
content-disposition: form-data; name="huge"; filename="huge"\r
\r
foo\r
EOF
    req = Rack::Request.new Rack::MockRequest.env_for("/",
                      "CONTENT_TYPE" => "multipart/form-data, boundary=AaB03x",
                      "CONTENT_LENGTH" => input.size,
                      :input => input)

    lambda { req.POST }.should.raise(EOFError)

    input = <<EOF
--AaB03x\r
content-disposition: form-data; name="huge"; filename="huge"\r
\r
foo\r
EOF
    req = Rack::Request.new Rack::MockRequest.env_for("/",
                      "CONTENT_TYPE" => "multipart/form-data, boundary=AaB03x",
                      "CONTENT_LENGTH" => input.size,
                      :input => input)

    lambda { req.POST }.should.raise(EOFError)
  end

  should "correctly parse the part name from Content-Id header" do
    input = <<EOF
--AaB03x\r
Content-Type: text/xml; charset=utf-8\r
Content-Id: <soap-start>\r
Content-Transfer-Encoding: 7bit\r
\r
foo\r
--AaB03x--\r
EOF
    req = Rack::Request.new Rack::MockRequest.env_for("/",
                      "CONTENT_TYPE" => "multipart/related, boundary=AaB03x",
                      "CONTENT_LENGTH" => input.size,
                      :input => input)

    req.params.keys.should.equal ["<soap-start>"]
  end

  should "not try to interpret binary as utf8" do
    if /regexp/.respond_to?(:kcode) # < 1.9
      begin
        original_kcode = $KCODE
        $KCODE='UTF8'

        input = <<EOF
--AaB03x\r
content-disposition: form-data; name="fileupload"; filename="junk.a"\r
content-type: application/octet-stream\r
\r
#{[0x36,0xCF,0x0A,0xF8].pack('c*')}\r
--AaB03x--\r
EOF

        req = Rack::Request.new Rack::MockRequest.env_for("/",
                          "CONTENT_TYPE" => "multipart/form-data, boundary=AaB03x",
                          "CONTENT_LENGTH" => input.size,
                          :input => input)

        lambda{req.POST}.should.not.raise(EOFError)
        req.POST["fileupload"][:tempfile].size.should.equal 4
      ensure
        $KCODE = original_kcode
      end
    else # >= 1.9
        input = <<EOF
--AaB03x\r
content-disposition: form-data; name="fileupload"; filename="junk.a"\r
content-type: application/octet-stream\r
\r
#{[0x36,0xCF,0x0A,0xF8].pack('c*')}\r
--AaB03x--\r
EOF

      req = Rack::Request.new Rack::MockRequest.env_for("/",
                        "CONTENT_TYPE" => "multipart/form-data, boundary=AaB03x",
                        "CONTENT_LENGTH" => input.size,
                        :input => input)

      lambda{req.POST}.should.not.raise(EOFError)
      req.POST["fileupload"][:tempfile].size.should.equal 4
    end
  end

  should "work around buggy 1.8.* Tempfile equality" do
    input = <<EOF
--AaB03x\r
content-disposition: form-data; name="huge"; filename="huge"\r
\r
foo\r
--AaB03x--
EOF

    rack_input = Tempfile.new("rackspec")
    rack_input.write(input)
    rack_input.rewind

    req = Rack::Request.new Rack::MockRequest.env_for("/",
                      "CONTENT_TYPE" => "multipart/form-data, boundary=AaB03x",
                      "CONTENT_LENGTH" => input.size,
                      :input => rack_input)

    lambda{ req.POST }.should.not.raise
    lambda{ req.POST }.should.not.raise("input re-processed!")
  end

  should "conform to the Rack spec" do
    app = lambda { |env|
      content = Rack::Request.new(env).POST["file"].inspect
      size = content.respond_to?(:bytesize) ? content.bytesize : content.size
      [200, {"Content-Type" => "text/html", "Content-Length" => size.to_s}, [content]]
    }

    input = <<EOF
--AaB03x\r
content-disposition: form-data; name="reply"\r
\r
yes\r
--AaB03x\r
content-disposition: form-data; name="fileupload"; filename="dj.jpg"\r
Content-Type: image/jpeg\r
Content-Transfer-Encoding: base64\r
\r
/9j/4AAQSkZJRgABAQAAAQABAAD//gA+Q1JFQVRPUjogZ2QtanBlZyB2MS4wICh1c2luZyBJSkcg\r
--AaB03x--\r
EOF
    input.force_encoding("ASCII-8BIT") if input.respond_to? :force_encoding
    res = Rack::MockRequest.new(Rack::Lint.new(app)).get "/",
      "CONTENT_TYPE" => "multipart/form-data, boundary=AaB03x",
      "CONTENT_LENGTH" => input.size.to_s, "rack.input" => StringIO.new(input)

    res.should.be.ok
  end

  should "parse Accept-Encoding correctly" do
    parser = lambda do |x|
      Rack::Request.new(Rack::MockRequest.env_for("", "HTTP_ACCEPT_ENCODING" => x)).accept_encoding
    end

    parser.call(nil).should.equal([])

    parser.call("compress, gzip").should.equal([["compress", 1.0], ["gzip", 1.0]])
    parser.call("").should.equal([])
    parser.call("*").should.equal([["*", 1.0]])
    parser.call("compress;q=0.5, gzip;q=1.0").should.equal([["compress", 0.5], ["gzip", 1.0]])
    parser.call("gzip;q=1.0, identity; q=0.5, *;q=0").should.equal([["gzip", 1.0], ["identity", 0.5], ["*", 0] ])

    parser.call("gzip ; q=0.9").should.equal([["gzip", 0.9]])
    parser.call("gzip ; deflate").should.equal([["gzip", 1.0]])
  end

  ip_app = lambda { |env|
    request = Rack::Request.new(env)
    response = Rack::Response.new
    response.write request.ip
    response.finish
  }

  should 'provide ip information' do
    mock = Rack::MockRequest.new(Rack::Lint.new(ip_app))

    res = mock.get '/', 'REMOTE_ADDR' => '1.2.3.4'
    res.body.should.equal '1.2.3.4'

    res = mock.get '/', 'REMOTE_ADDR' => 'fe80::202:b3ff:fe1e:8329'
    res.body.should.equal 'fe80::202:b3ff:fe1e:8329'

    res = mock.get '/', 'REMOTE_ADDR' => '1.2.3.4,3.4.5.6'
    res.body.should.equal '1.2.3.4'
  end

  should 'deals with proxies' do
    mock = Rack::MockRequest.new(Rack::Lint.new(ip_app))

    res = mock.get '/',
      'REMOTE_ADDR' => '1.2.3.4',
      'HTTP_X_FORWARDED_FOR' => '3.4.5.6'
    res.body.should.equal '1.2.3.4'

    res = mock.get '/',
      'REMOTE_ADDR' => '127.0.0.1',
      'HTTP_X_FORWARDED_FOR' => '3.4.5.6'
    res.body.should.equal '3.4.5.6'

    res = mock.get '/', 'HTTP_X_FORWARDED_FOR' => 'unknown,3.4.5.6'
    res.body.should.equal '3.4.5.6'

    res = mock.get '/', 'HTTP_X_FORWARDED_FOR' => '192.168.0.1,3.4.5.6'
    res.body.should.equal '3.4.5.6'

    res = mock.get '/', 'HTTP_X_FORWARDED_FOR' => '10.0.0.1,3.4.5.6'
    res.body.should.equal '3.4.5.6'

    res = mock.get '/', 'HTTP_X_FORWARDED_FOR' => '10.0.0.1, 10.0.0.1, 3.4.5.6'
    res.body.should.equal '3.4.5.6'

    res = mock.get '/', 'HTTP_X_FORWARDED_FOR' => '127.0.0.1, 3.4.5.6'
    res.body.should.equal '3.4.5.6'

    res = mock.get '/', 'HTTP_X_FORWARDED_FOR' => 'unknown,192.168.0.1'
    res.body.should.equal 'unknown'

    res = mock.get '/', 'HTTP_X_FORWARDED_FOR' => 'other,unknown,192.168.0.1'
    res.body.should.equal 'unknown'

    res = mock.get '/', 'HTTP_X_FORWARDED_FOR' => 'unknown,localhost,192.168.0.1'
    res.body.should.equal 'unknown'

    res = mock.get '/', 'HTTP_X_FORWARDED_FOR' => '9.9.9.9, 3.4.5.6, 10.0.0.1, 172.31.4.4'
    res.body.should.equal '3.4.5.6'

    res = mock.get '/', 'HTTP_X_FORWARDED_FOR' => '::1,2620:0:1c00:0:812c:9583:754b:ca11'
    res.body.should.equal '2620:0:1c00:0:812c:9583:754b:ca11'

    res = mock.get '/', 'HTTP_X_FORWARDED_FOR' => '2620:0:1c00:0:812c:9583:754b:ca11,::1'
    res.body.should.equal '2620:0:1c00:0:812c:9583:754b:ca11'

    res = mock.get '/', 'HTTP_X_FORWARDED_FOR' => 'fd5b:982e:9130:247f:0000:0000:0000:0000,2620:0:1c00:0:812c:9583:754b:ca11'
    res.body.should.equal '2620:0:1c00:0:812c:9583:754b:ca11'

    res = mock.get '/', 'HTTP_X_FORWARDED_FOR' => '2620:0:1c00:0:812c:9583:754b:ca11,fd5b:982e:9130:247f:0000:0000:0000:0000'
    res.body.should.equal '2620:0:1c00:0:812c:9583:754b:ca11'

    res = mock.get '/',
      'HTTP_X_FORWARDED_FOR' => '1.1.1.1, 127.0.0.1',
      'HTTP_CLIENT_IP' => '1.1.1.1'
    res.body.should.equal '1.1.1.1'

    # Spoofing attempt
    res = mock.get '/',
      'HTTP_X_FORWARDED_FOR' => '1.1.1.1',
      'HTTP_CLIENT_IP' => '2.2.2.2'
    res.body.should.equal '1.1.1.1'

    res = mock.get '/', 'HTTP_X_FORWARDED_FOR' => '8.8.8.8, 9.9.9.9'
    res.body.should.equal '9.9.9.9'

    res = mock.get '/', 'HTTP_X_FORWARDED_FOR' => '8.8.8.8, fe80::202:b3ff:fe1e:8329'
    res.body.should.equal 'fe80::202:b3ff:fe1e:8329'
  end

  class MyRequest < Rack::Request
    def params
      {:foo => "bar"}
    end
  end

  should "allow subclass request to be instantiated after parent request" do
    env = Rack::MockRequest.env_for("/?foo=bar")

    req1 = Rack::Request.new(env)
    req1.GET.should.equal "foo" => "bar"
    req1.params.should.equal "foo" => "bar"

    req2 = MyRequest.new(env)
    req2.GET.should.equal "foo" => "bar"
    req2.params.should.equal :foo => "bar"
  end

  should "allow parent request to be instantiated after subclass request" do
    env = Rack::MockRequest.env_for("/?foo=bar")

    req1 = MyRequest.new(env)
    req1.GET.should.equal "foo" => "bar"
    req1.params.should.equal :foo => "bar"

    req2 = Rack::Request.new(env)
    req2.GET.should.equal "foo" => "bar"
    req2.params.should.equal "foo" => "bar"
  end

  (0x20...0x7E).collect { |a|
    b = a.chr
    c = CGI.escape(b)
    should "not strip '#{a}' => '#{c}' => '#{b}' escaped character from parameters when accessed as string" do
      url = "/?foo=#{c}bar#{c}"
      env = Rack::MockRequest.env_for(url)
      req2 = Rack::Request.new(env)
      req2.GET.should.equal "foo" => "#{b}bar#{b}"
      req2.params.should.equal "foo" => "#{b}bar#{b}"
    end
  }
end
