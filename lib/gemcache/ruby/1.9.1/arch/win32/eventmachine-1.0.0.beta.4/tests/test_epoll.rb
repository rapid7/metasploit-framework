require 'em_test_helper'


class TestEpoll < Test::Unit::TestCase

  module TestEchoServer
    def receive_data data
      send_data data
      close_connection_after_writing
    end
  end

  module TestEchoClient
    def connection_completed
      send_data "ABCDE"
      $max += 1
    end
    def receive_data data
      raise "bad response" unless data == "ABCDE"
    end
    def unbind
      $n -= 1
      EM.stop if $n == 0
    end
  end


  if windows? || jruby?
    warn "EM.set_descriptor_table_size not implemented, skipping test in #{__FILE__}"
  else
    # We can set the rlimit/nofile of a process but we can only set it
    # higher if we're running as root.
    # On most systems, the default value is 1024.
    def test_rlimit
      unless EM.set_descriptor_table_size >= 1024
        a = EM.set_descriptor_table_size
        assert( a <= 1024 )
        a = EM.set_descriptor_table_size( 1024 )
        assert( a == 1024 )
      end
    end
  end

  # Run a high-volume version of this test by kicking the number of connections
  # up past 512. (Each connection uses two sockets, a client and a server.)
  # (Will require running the test as root)
  # This test exercises TCP clients and servers.
  #
  # XXX this test causes all sort of weird issues on OSX (when run as part of the suite)
  def _test_descriptors
    EM.epoll
    EM.set_descriptor_table_size 60000
    EM.run {
      EM.start_server "127.0.0.1", 9800, TestEchoServer
      $n = 0
      $max = 0
      100.times {
        EM.connect("127.0.0.1", 9800, TestEchoClient) {$n += 1}
      }
    }
    assert_equal(0, $n)
    assert_equal(100, $max)
  end

  def setup
    @port = next_port
  end

  module TestDatagramServer
    def receive_data dgm
      $in = dgm
      send_data "abcdefghij"
    end
  end
  module TestDatagramClient
    def initialize port
      @port = port
    end

    def post_init
      send_datagram "1234567890", "127.0.0.1", @port
    end

    def receive_data dgm
      $out = dgm
      EM.stop
    end
  end

  def test_datagrams
    $in = $out = ""
    EM.run {
      EM.open_datagram_socket "127.0.0.1", @port, TestDatagramServer
      EM.open_datagram_socket "127.0.0.1", 0, TestDatagramClient, @port
    }
    assert_equal( "1234567890", $in )
    assert_equal( "abcdefghij", $out )
  end

  # XXX this test fails randomly..
  def _test_unix_domain
    fn = "/tmp/xxx.chain"
    EM.epoll
    EM.set_descriptor_table_size 60000
    EM.run {
      # The pure-Ruby version won't let us open the socket if the node already exists.
      # Not sure, that actually may be correct and the compiled version is wrong.
      # Pure Ruby also oddly won't let us make that many connections. This test used
      # to run 100 times. Not sure where that lower connection-limit is coming from in
      # pure Ruby.
      # Let's not sweat the Unix-ness of the filename, since this test can't possibly
      # work on Windows anyway.
      #
      File.unlink(fn) if File.exist?(fn)
      EM.start_unix_domain_server fn, TestEchoServer
      $n = 0
      $max = 0
      50.times {
        EM.connect_unix_domain(fn, TestEchoClient) {$n += 1}
      }
      EM::add_timer(1) { $stderr.puts("test_unix_domain timed out!"); EM::stop }
    }
    assert_equal(0, $n)
    assert_equal(50, $max)
  ensure
    File.unlink(fn) if File.exist?(fn)
  end

end

