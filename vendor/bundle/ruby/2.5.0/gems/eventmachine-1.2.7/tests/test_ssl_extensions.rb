require 'em_test_helper'

require 'socket'
require 'openssl'

if EM.ssl?
  class TestSslExtensions < Test::Unit::TestCase

    module Client
      def ssl_handshake_completed
        $client_handshake_completed = true
        close_connection
      end

      def unbind
        EM.stop_event_loop
      end

      def post_init
        start_tls(:ssl_version => :tlsv1, :sni_hostname => 'example.com')
      end
    end

    module Server
      def ssl_handshake_completed
        $server_handshake_completed = true
        $server_sni_hostname = get_sni_hostname
      end

      def post_init
        start_tls(:ssl_version => :TLSv1)
      end
    end

    def test_tlsext_sni_hostname
      $server_handshake_completed = false

      EM.run do
        EM.start_server("127.0.0.1", 16784, Server)
        EM.connect("127.0.0.1", 16784, Client)
      end

      assert($server_handshake_completed)
      assert_equal('example.com', $server_sni_hostname)
    end
  end
else
  warn "EM built without SSL support, skipping tests in #{__FILE__}"
end
