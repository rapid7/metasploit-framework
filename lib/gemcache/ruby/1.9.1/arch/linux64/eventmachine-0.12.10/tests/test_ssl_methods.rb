$:.unshift "../lib"
require 'eventmachine'
require 'test/unit'

class TestSSLMethods < Test::Unit::TestCase

  module ServerHandler

    def post_init
      start_tls
    end

    def ssl_handshake_completed
      $server_called_back = true
      $server_cert_value = get_peer_cert
    end

  end

  module ClientHandler

    def post_init
      start_tls
    end

    def ssl_handshake_completed
      $client_called_back = true
      $client_cert_value = get_peer_cert
      EM.stop_event_loop
    end

  end

  def test_ssl_methods
    $server_called_back, $client_called_back = false, false
    $server_cert_value, $client_cert_value = nil, nil

    EM.run {
      EM.start_server("127.0.0.1", 9999, ServerHandler)
      EM.connect("127.0.0.1", 9999, ClientHandler)
    }

    assert($server_called_back)
    assert($client_called_back)

    assert($server_cert_value.is_a?(NilClass))
    assert($client_cert_value.is_a?(String))
  end

end if EM.ssl?