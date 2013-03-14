require 'em_test_helper'

class TestHeaderAndContentProtocol < Test::Unit::TestCase

  class SimpleTest < EM::P::HeaderAndContentProtocol
    attr_reader :first_header, :my_headers, :request

    def receive_first_header_line hdr
      @first_header ||= []
      @first_header << hdr
    end
    def receive_headers hdrs
      @my_headers ||= []
      @my_headers << hdrs
    end
    def receive_request hdrs, content
      @request ||= []
      @request << [hdrs, content]
    end
  end
  
  class StopOnUnbind < EM::Connection
    def unbind
      EM.add_timer(0.01) { EM.stop }
    end
  end

  def setup
    @port = next_port
  end

  def test_no_content
    the_connection = nil
    EM.run {
      EM.start_server( "127.0.0.1", @port, SimpleTest ) do |conn|
        the_connection = conn
      end
      setup_timeout

      EM.connect "127.0.0.1", @port, StopOnUnbind do |c|
        c.send_data [ "aaa\n", "bbb\r\n", "ccc\n", "\n" ].join
        c.close_connection_after_writing
      end
    }
    assert_equal( ["aaa"], the_connection.first_header )
    assert_equal( [%w(aaa bbb ccc)], the_connection.my_headers )
    assert_equal( [[%w(aaa bbb ccc), ""]], the_connection.request )
  end

  def test_content
    the_connection = nil
    content = "A" * 50
    headers = ["aaa", "bbb", "Content-length: #{content.length}", "ccc"]
    EM.run {
      EM.start_server( "127.0.0.1", @port, SimpleTest ) do |conn|
        the_connection = conn
      end
      setup_timeout

      EM.connect "127.0.0.1", @port, StopOnUnbind do |c|
        headers.each { |h| c.send_data "#{h}\r\n" }
        c.send_data "\n"
        c.send_data content
        c.close_connection_after_writing
      end
    }
    assert_equal( ["aaa"], the_connection.first_header )
    assert_equal( [headers], the_connection.my_headers )
    assert_equal( [[headers, content]], the_connection.request )
  end

  def test_several_requests
    the_connection = nil
    content = "A" * 50
    headers = ["aaa", "bbb", "Content-length: #{content.length}", "ccc"]
    EM.run {
      EM.start_server( "127.0.0.1", @port, SimpleTest ) do |conn|
        the_connection = conn
      end
      setup_timeout

      EM.connect( "127.0.0.1", @port, StopOnUnbind ) do |c|
        5.times do
          headers.each { |h| c.send_data "#{h}\r\n" }
          c.send_data "\n"
          c.send_data content
        end
        c.close_connection_after_writing
      end
    }
    assert_equal( ["aaa"] * 5, the_connection.first_header )
    assert_equal( [headers] * 5, the_connection.my_headers )
    assert_equal( [[headers, content]] * 5, the_connection.request )
  end


  # def x_test_multiple_content_length_headers
  #   # This is supposed to throw a RuntimeError but it throws a C++ exception instead.
  #   the_connection = nil
  #   content = "A" * 50
  #   headers = ["aaa", "bbb", ["Content-length: #{content.length}"]*2, "ccc"].flatten
  #   EM.run {
  #     EM.start_server( "127.0.0.1", @port, SimpleTest ) do |conn|
  #       the_connection = conn
  #     end
  #     EM.add_timer(4) {raise "test timed out"}
  #     test_proc = proc {
  #       t = TCPSocket.new "127.0.0.1", @port
  #       headers.each {|h| t.write "#{h}\r\n" }
  #       t.write "\n"
  #       t.write content
  #       t.close
  #     }
  #     EM.defer test_proc, proc {
  #       EM.stop
  #     }
  #   }
  # end

  def test_interpret_headers
    the_connection = nil
    content = "A" * 50
    headers = [
      "GET / HTTP/1.0",
      "Accept: aaa",
      "User-Agent: bbb",
      "Host: ccc",
      "x-tempest-header:ddd"
    ]

    EM.run {
      EM.start_server( "127.0.0.1", @port, SimpleTest ) do |conn|
        the_connection = conn
      end
      setup_timeout

      EM.connect( "127.0.0.1", @port, StopOnUnbind ) do |c|
        headers.each { |h| c.send_data "#{h}\r\n" }
        c.send_data "\n"
        c.send_data content
        c.close_connection_after_writing
      end
    }

    hsh = the_connection.headers_2_hash( the_connection.my_headers.shift )
    expect = {
      :accept => "aaa",
      :user_agent => "bbb",
      :host => "ccc",
      :x_tempest_header => "ddd"
    }
    assert_equal(expect, hsh)
  end

end
