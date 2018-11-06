require 'em_test_helper'

class TestHttpClient2 < Test::Unit::TestCase
  class TestServer < EM::Connection
  end

  def setup
    @port = next_port
  end

  # #connect returns an object which has made a connection to an HTTP server
  # and exposes methods for making HTTP requests on that connection.
  # #connect can take either a pair of parameters (a host and a port),
  # or a single parameter which is a Hash.
  #
  def test_connect
    EM.run {
      setup_timeout(1)
      EM.start_server '127.0.0.1', @port, TestServer
      silent do
        EM::P::HttpClient2.connect '127.0.0.1', @port
        EM::P::HttpClient2.connect( :host=>'127.0.0.1', :port=>@port )
      end
      EM.stop
    }
  end

  def test_bad_port
    EM.run {
      setup_timeout(1)
      EM.start_server '127.0.0.1', @port, TestServer
      assert_raises( ArgumentError ) {
        silent { EM::P::HttpClient2.connect '127.0.0.1', "xxx" }
      }
      EM.stop
    }
  end

  def test_bad_server
    err = nil
    EM.run {
      setup_timeout(1)
      http = silent { EM::P::HttpClient2.connect '127.0.0.1', 9999 }
      d = http.get "/"
      d.errback { err = true; d.internal_error; EM.stop }
    }
    assert(err)
  end

  def test_get
    content = nil
    EM.run {
      setup_timeout(1)
      http = silent { EM::P::HttpClient2.connect :host => "google.com", :port => 80, :version => '1.0' }
      d = http.get "/"
      d.callback {
        content = d.content
        EM.stop
      }
    }
    assert(content)
  end

  # Not a pipelined request because we wait for one response before we request the next.
  # XXX this test is broken because it sends the second request to the first connection
  # XXX right before the connection closes
  def _test_get_multiple
    content = nil
    EM.run {
      setup_timeout(1)
      http = silent { EM::P::HttpClient2.connect "google.com", :version => '1.0' }
      d = http.get "/"
      d.callback {
        e = http.get "/"
        e.callback {
          content = e.content
          EM.stop
        }
      }
    }
    assert(content)
  end

  def test_get_pipeline
    headers, headers2 = nil, nil
    EM.run {
      setup_timeout(1)
      http = silent { EM::P::HttpClient2.connect "google.com", 80 }
      d = http.get("/")
      d.callback {
        headers = d.headers
      }
      e = http.get("/")
      e.callback {
        headers2 = e.headers
      }
      EM.tick_loop { EM.stop if headers && headers2 }
      EM.add_timer(1) { EM.stop }
    }
    assert(headers)
    assert(headers2)
  end

  def test_authheader
    EM.run {
      setup_timeout(1)
      EM.start_server '127.0.0.1', @port, TestServer
      http = silent { EM::P::HttpClient2.connect '127.0.0.1', 18842 }
      d = http.get :url=>"/", :authorization=>"Basic xxx"
      d.callback {EM.stop}
      d.errback {EM.stop}
    }
  end

  def test_https_get
    omit_unless(EM.ssl?)
    d = nil
    EM.run {
      setup_timeout(1)
      http = silent { EM::P::HttpClient2.connect :host => 'www.google.com', :port => 443, :ssl => true, :version => '1.0' }
      d = http.get "/"
      d.callback {EM.stop}
      d.errback {EM.stop}
    }
    assert_equal(200, d.status)
  end

end
