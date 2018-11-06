require 'em_test_helper'

require 'socket'
require 'openssl'

if EM.ssl?
  class TestSslProtocols < Test::Unit::TestCase

    module Client
      def ssl_handshake_completed
        $client_handshake_completed = true
        close_connection
      end

      def unbind
        EM.stop_event_loop
      end
    end

    module Server
      def ssl_handshake_completed
        $server_handshake_completed = true
      end
    end

    module ClientAny
      include Client
      def post_init
        start_tls(:ssl_version => %w(sslv2 sslv3 tlsv1 tlsv1_1 tlsv1_2))
      end
    end

    module ClientDefault
      include Client
      def post_init
        start_tls
      end
    end

    module ClientSSLv3
      include Client
      def post_init
        start_tls(:ssl_version => %w(SSLv3))
      end
    end

    module ServerSSLv3
      include Server
      def post_init
        start_tls(:ssl_version => %w(SSLv3))
      end
    end

    module ServerTLSv1CaseInsensitive
      include Server
      def post_init
        start_tls(:ssl_version => %w(tlsv1))
      end
    end

    module ServerAny
      include Server
      def post_init
        start_tls(:ssl_version => %w(sslv2 sslv3 tlsv1 tlsv1_1 tlsv1_2))
      end
    end

    module ServerDefault
      include Server
      def post_init
        start_tls
      end
    end

    module InvalidProtocol
      include Client
      def post_init
        start_tls(:ssl_version => %w(tlsv1 badinput))
      end
    end

    def test_invalid_ssl_version
      assert_raises(RuntimeError, "Unrecognized SSL/TLS Version: badinput") do
        EM.run do
          EM.start_server("127.0.0.1", 16784, InvalidProtocol)
          EM.connect("127.0.0.1", 16784, InvalidProtocol)
        end
      end
    end

    def test_any_to_v3
      $client_handshake_completed, $server_handshake_completed = false, false
      EM.run do
        EM.start_server("127.0.0.1", 16784, ServerSSLv3)
        EM.connect("127.0.0.1", 16784, ClientAny)
      end

      assert($client_handshake_completed)
      assert($server_handshake_completed)
    end

    def test_case_insensitivity
      $client_handshake_completed, $server_handshake_completed = false, false
      EM.run do
        EM.start_server("127.0.0.1", 16784, ServerTLSv1CaseInsensitive)
        EM.connect("127.0.0.1", 16784, ClientAny)
      end

      assert($client_handshake_completed)
      assert($server_handshake_completed)
    end

    def test_v3_to_any
      $client_handshake_completed, $server_handshake_completed = false, false
      EM.run do
        EM.start_server("127.0.0.1", 16784, ServerAny)
        EM.connect("127.0.0.1", 16784, ClientSSLv3)
      end

      assert($client_handshake_completed)
      assert($server_handshake_completed)
    end

    def test_v3_to_v3
      $client_handshake_completed, $server_handshake_completed = false, false
      EM.run do
        EM.start_server("127.0.0.1", 16784, ServerSSLv3)
        EM.connect("127.0.0.1", 16784, ClientSSLv3)
      end

      assert($client_handshake_completed)
      assert($server_handshake_completed)
    end

    def test_any_to_any
      $client_handshake_completed, $server_handshake_completed = false, false
      EM.run do
        EM.start_server("127.0.0.1", 16784, ServerAny)
        EM.connect("127.0.0.1", 16784, ClientAny)
      end

      assert($client_handshake_completed)
      assert($server_handshake_completed)
    end

    def test_default_to_default
      $client_handshake_completed, $server_handshake_completed = false, false
      EM.run do
        EM.start_server("127.0.0.1", 16784, ServerDefault)
        EM.connect("127.0.0.1", 16784, ClientDefault)
      end

      assert($client_handshake_completed)
      assert($server_handshake_completed)
    end

    module ServerV3StopAfterHandshake
      def post_init
        start_tls(:ssl_version => %w(SSLv3))
      end

      def ssl_handshake_completed
        $server_handshake_completed = true
        EM.stop_event_loop
      end
    end

    module ServerTLSv1StopAfterHandshake
      def post_init
        start_tls(:ssl_version => %w(TLSv1))
      end

      def ssl_handshake_completed
        $server_handshake_completed = true
        EM.stop_event_loop
      end
    end

    def test_v3_with_external_client
      $server_handshake_completed = false
      EM.run do
        setup_timeout(2)
        EM.start_server("127.0.0.1", 16784, ServerV3StopAfterHandshake)
        EM.defer do
          sock = TCPSocket.new("127.0.0.1", 16784)
          ctx = OpenSSL::SSL::SSLContext.new
          ctx.ssl_version = :SSLv3_client
          ssl = OpenSSL::SSL::SSLSocket.new(sock, ctx)
          ssl.connect
          ssl.close rescue nil
          sock.close rescue nil
        end
      end

      assert($server_handshake_completed)
    end

    def test_tlsv1_with_external_client
      $server_handshake_completed = false
      EM.run do
        setup_timeout(2)
        EM.start_server("127.0.0.1", 16784, ServerTLSv1StopAfterHandshake)
        EM.defer do
          sock = TCPSocket.new("127.0.0.1", 16784)
          ctx = OpenSSL::SSL::SSLContext.new
          ctx.ssl_version = :TLSv1_client
          ssl = OpenSSL::SSL::SSLSocket.new(sock, ctx)
          ssl.connect
          ssl.close rescue nil
          sock.close rescue nil
        end
      end

      assert($server_handshake_completed)
    end

    def test_tlsv1_required_with_external_client
      $server_handshake_completed = false

      EM.run do
        n = 0
        EM.add_periodic_timer(0.5) do
          n += 1
          (EM.stop rescue nil) if n == 2
        end
        EM.start_server("127.0.0.1", 16784, ServerTLSv1StopAfterHandshake)
        EM.defer do
          sock = TCPSocket.new("127.0.0.1", 16784)
          ctx = OpenSSL::SSL::SSLContext.new
          ctx.ssl_version = :SSLv3_client
          ssl = OpenSSL::SSL::SSLSocket.new(sock, ctx)
          assert_raise OpenSSL::SSL::SSLError do
            ssl.connect
          end
          ssl.close rescue nil
          sock.close rescue nil
          EM.stop rescue nil
        end
      end

      assert(!$server_handshake_completed)
    end
  end
else
  warn "EM built without SSL support, skipping tests in #{__FILE__}"
end
