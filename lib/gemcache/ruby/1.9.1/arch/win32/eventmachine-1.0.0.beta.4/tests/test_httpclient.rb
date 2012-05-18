require 'em_test_helper'

class TestHttpClient < Test::Unit::TestCase

    Localhost = "127.0.0.1"
    Localport = 9801

  def setup
  end

  def teardown
  end

  #-------------------------------------

  def test_http_client
    ok = false
    EM.run {
      c = silent { EM::P::HttpClient.send :request, :host => "www.google.com", :port => 80 }
      c.callback {
        ok = true
        EM.stop
      }
      c.errback {EM.stop} # necessary, otherwise a failure blocks the test suite forever.
    }
    assert ok
  end

  #-------------------------------------

  def test_http_client_1
    ok = false
    EM.run {
      c = silent { EM::P::HttpClient.send :request, :host => "www.google.com", :port => 80 }
      c.callback {ok = true; EM.stop}
      c.errback {EM.stop}
    }
    assert ok
  end

  #-------------------------------------

  def test_http_client_2
    ok = false
    EM.run {
      c = silent { EM::P::HttpClient.send :request, :host => "www.google.com", :port => 80 }
      c.callback {|result|
        ok = true;
        EM.stop
      }
      c.errback {EM.stop}
    }
    assert ok
  end


  #-----------------------------------------

  # Test a server that returns a page with a zero content-length.
  # This caused an early version of the HTTP client not to generate a response,
  # causing this test to hang. Observe, there was no problem with responses
  # lacking a content-length, just when the content-length was zero.
  #
  class EmptyContent < EM::Connection
      def initialize *args
        super
      end
      def receive_data data
        send_data "HTTP/1.0 404 ...\r\nContent-length: 0\r\n\r\n"
        close_connection_after_writing
      end
  end

  def test_http_empty_content
      ok = false
      EM.run {
        EM.start_server "127.0.0.1", 9701, EmptyContent
        c = silent { EM::P::HttpClient.send :request, :host => "127.0.0.1", :port => 9701 }
        c.callback {|result|
          ok = true
          EM.stop
        }
      }
      assert ok
  end


  #---------------------------------------

  class PostContent < EM::P::LineAndTextProtocol
      def initialize *args
        super
        @lines = []
      end
      def receive_line line
        if line.length > 0
          @lines << line
        else
          process_headers
        end
      end
      def receive_binary_data data
        @post_content = data
        send_response
      end
      def process_headers
        if @lines.first =~ /\APOST ([^\s]+) HTTP\/1.1\Z/
          @uri = $1.dup
        else
          raise "bad request"
        end

        @lines.each {|line|
          if line =~ /\AContent-length:\s*(\d+)\Z/i
            @content_length = $1.dup.to_i
          elsif line =~ /\AContent-type:\s*(\d+)\Z/i
            @content_type = $1.dup
          end
        }

        raise "invalid content length" unless @content_length
        set_binary_mode @content_length
      end
      def send_response
        send_data "HTTP/1.1 200 ...\r\nConnection: close\r\nContent-length: 10\r\nContent-type: text/html\r\n\r\n0123456789"
        close_connection_after_writing
      end
  end
  
  # TODO, this is WRONG. The handler is asserting an HTTP 1.1 request, but the client
  # is sending a 1.0 request. Gotta fix the client
  def test_post
      response = nil
      EM.run {
        EM.start_server Localhost, Localport, PostContent
        setup_timeout(2)
        c = silent { EM::P::HttpClient.request(
          :host=>Localhost,
          :port=>Localport,
          :method=>:post,
          :request=>"/aaa",
          :content=>"XYZ",
          :content_type=>"text/plain"
        )}
        c.callback {|r|
          response = r
          EM.stop
        }
      }

      assert_equal( 200, response[:status] )
      assert_equal( "0123456789", response[:content] )
  end


  # TODO, need a more intelligent cookie tester.
  # In fact, this whole test-harness needs a beefier server implementation.
  def test_cookie
    ok = false
    EM.run {
      c = silent { EM::Protocols::HttpClient.send :request, :host => "www.google.com", :port => 80, :cookie=>"aaa=bbb" }
      c.callback {|result|
        ok = true;
        EM.stop
      }
      c.errback {EM.stop}
    }
    assert ok
  end

  # We can tell the client to send an HTTP/1.0 request (default is 1.1).
  # This is useful for suppressing chunked responses until those are working.
  def test_version_1_0
    ok = false
    EM.run {
      c = silent { EM::P::HttpClient.request(
        :host => "www.google.com",
        :port => 80,
        :version => "1.0"
      )}
      c.callback {|result|
        ok = true;
        EM.stop
      }
      c.errback {EM.stop}
    }
    assert ok
  end

end
