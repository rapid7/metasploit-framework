require 'em_test_helper'

class TestIPv6 < Test::Unit::TestCase

  if Test::Unit::TestCase.public_ipv6?

    # Runs a TCP server in the local IPv6 address, connects to it and sends a specific data.
    # Timeout in 2 seconds.
    def test_ipv6_tcp_local_server
      @@received_data = nil
      @local_port = next_port
      setup_timeout(2)

      EM.run do
        EM.start_server(@@public_ipv6, @local_port) do |s|
          def s.receive_data data
            @@received_data = data
            EM.stop
          end
        end

        EM::connect(@@public_ipv6, @local_port) do |c|
          def c.unbind(reason)
            warn "unbind: #{reason.inspect}" if reason # XXX at least find out why it failed
          end
          c.send_data "ipv6/tcp"
        end
      end

      assert_equal "ipv6/tcp", @@received_data
    end

    # Runs a UDP server in the local IPv6 address, connects to it and sends a specific data.
    # Timeout in 2 seconds.
    def test_ipv6_udp_local_server
      @@received_data = nil
      @local_port = next_port
      @@remote_ip = nil
      setup_timeout(2)

      EM.run do
        EM.open_datagram_socket(@@public_ipv6, @local_port) do |s|
          def s.receive_data data
            _port, @@remote_ip = Socket.unpack_sockaddr_in(get_peername)
            @@received_data = data
            EM.stop
          end
        end

        EM.open_datagram_socket(@@public_ipv6, next_port) do |c|
          c.send_datagram "ipv6/udp", @@public_ipv6, @local_port
        end
      end
      assert_equal @@remote_ip, @@public_ipv6
      assert_equal "ipv6/udp", @@received_data
    end

    # Try to connect via TCP to an invalid IPv6. EM.connect should raise
    # EM::ConnectionError.
    def test_tcp_connect_to_invalid_ipv6
      invalid_ipv6 = "1:A"

      EM.run do
        begin
          error = nil
          EM.connect(invalid_ipv6, 1234)
        rescue => e
          error = e
        ensure
          EM.stop
          assert_equal EM::ConnectionError, (error && error.class)
        end
      end
    end

    # Try to send a UDP datagram to an invalid IPv6. EM.send_datagram should raise
    # EM::ConnectionError.
    def test_udp_send_datagram_to_invalid_ipv6
      invalid_ipv6 = "1:A"

      EM.run do
        begin
          error = nil
          EM.open_datagram_socket(@@public_ipv6, next_port) do |c|
            c.send_datagram "hello", invalid_ipv6, 1234
          end
        rescue => e
          error = e
        ensure
          EM.stop
          assert_equal EM::ConnectionError, (error && error.class)
        end
      end
    end


  else
    warn "no IPv6 in this host, skipping tests in #{__FILE__}"

    # Because some rubies will complain if a TestCase class has no tests.
    def test_ipv6_unavailable
      assert true
    end

  end

end
