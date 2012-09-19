##
## $Release: 2.7.0 $
## copyright(c) 2006-2011 kuwata-lab.com all rights reserved.
##

require "#{File.dirname(__FILE__)}/test.rb"

require 'stringio'

load "#{File.dirname(__FILE__)}/../public_html/index.cgi"


def spec(desc)
  yield
end


def dummy_env(request_method='GET', request_uri='/', opts={})
  if request_method.is_a?(Hash)
    opts = request_method
    request_method = 'GET'
    request_uri = '/'
  elsif request_uri.is_a?(Hash)
    opts = request_uri
    request_uri = '/'
  end
  env = {
    'REQUEST_METHOD' => request_method.to_s,
    'REQUEST_URI'    => request_uri.to_s,
    'DOCUMENT_ROOT'  => Dir.pwd,
  }
  opts.each {|k, v| env[k.to_s.upcase] = v }
  env.update(opts)
  return env
end


def dummy_template(filename, content)
  begin
    File.open(filename, 'wb') {|f| f.write(content) }
    return yield
  ensure
    [filename, filename + '.cache'].each do |fname|
      File.unlink(fname) if File.exist?(fname)
    end
  end
end


class ErubisHandlerTest < Test::Unit::TestCase

  def test_initialize

    spec "sets @encoding and @layout" do
      encoding_bkup = $ENCODING
      layout_bkup   = $LAYOUT
      begin
        $ENCODING = 'cp932'
        $LAYOUT   = 'site.rhtml'
        obj = ErubisHandler.new
        assert_equal 'cp932', obj.encoding
        assert_equal 'site.rhtml', obj.layout
      ensure
        $ENCODING = encoding_bkup
        $LAYOUT   = layout_bkup
      end
    end

  end

  def test_handle

    spec "renders requested template file." do
      base = "_test_handle"
      env = dummy_env('GET', "/#{base}.html")
      handler = ErubisHandler.new
      input = <<'END'
<h1><%= '<b>SOS</b>' %></h1>
<ul>
  <% for item in %w[Haruhi Mikuru Yuki] %>
  <li><%= item %></li>
  <% end %>
</ul>
END
      expected = <<'END'
<h1><b>SOS</b></h1>
<ul>
  <li>Haruhi</li>
  <li>Mikuru</li>
  <li>Yuki</li>
</ul>
END
      out = dummy_template("#{base}.rhtml", input) do
        handler.handle(env)
      end
      assert_equal expected, out
    end

    spec "raises 404 error when requested file not found." do
      req_url = "/_test_handle.html"
      env = dummy_env('GET', req_url)
      handler = ErubisHandler.new
      ex = assert_raise HttpError do
        handler.handle(env)
      end
      assert_equal 404, ex.status
      assert_equal "#{req_url}: not found.", ex.message
    end

  end

end


class ErubisApplicationTest < Test::Unit::TestCase

  def test_handle_request

    spec "handles request by handler object and returns response data." do
      app = ErubisApplication.new()
      def app.get_handler
        return Class.new {
          def handle(env); "<p>Hello SOS</p>"; end
          def encoding; "euc_jp"; end
        }.new
      end
      expected = [
        200,
        [["Content-Type", "text/html;charset=euc_jp"]],
        ["<p>Hello SOS</p>"],
      ]
      env = dummy_env('GET', '/')
      ret = app.call(env)
      assert_equal expected, ret
    end

  end

  def test_handle_http_error

    spec "renders error page." do
      req_path = '/HaruhiSuzumiya.html'
      app = ErubisApplication.new()
      env = dummy_env('GET', req_path)
      expected = [
        404,
        [["Content-Type", "text/html"]],
        ["<h2>404 Not Found</h2>\n<p>#{req_path}: not found.</p>\n"],
      ]
      ret = app.call(env)
      assert_equal expected, ret
    end

  end

  def test_run

    spec "prints to $stdout" do
      input = "<p>Hello SOS</p>"
      app = ErubisApplication.new
      base = "SOS"
      env = dummy_env("GET", "/#{base}.html")
      sio = StringIO.new
      output = dummy_template("#{base}.rhtml", input) do
        app.run(env, sio)
        sio.string
      end
      expected = ""
      expected << "Content-Type: text/html\r\n"
      expected << "\r\n"
      expected << "<p>Hello SOS</p>"
      assert_equal expected, output
    end

    spec "prints 'Status:' header if status code is not 200." do
      req_path = "/SOS.html"
      env = dummy_env("GET", req_path)
      app = ErubisApplication.new
      sio = StringIO.new
      app.run(env, sio)
      expected = "Status: 404 Not Found\r\n"
      expected << "Content-Type: text/html\r\n"
      expected << "\r\n"
      expected << "<h2>404 Not Found</h2>\n"
      expected << "<p>#{req_path}: not found.</p>\n"
      assert_equal expected, sio.string
    end

  end

end
