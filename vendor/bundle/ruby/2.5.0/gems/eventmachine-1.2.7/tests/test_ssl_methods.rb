require 'em_test_helper'

class TestSSLMethods < Test::Unit::TestCase

  module ServerHandler
    def post_init
      start_tls
    end

    def ssl_handshake_completed
      $server_called_back = true
      $server_cert_value = get_peer_cert
      $server_cipher_bits = get_cipher_bits
      $server_cipher_name = get_cipher_name
      $server_cipher_protocol = get_cipher_protocol
    end
  end

  module ClientHandler
    def post_init
      start_tls
    end

    def ssl_handshake_completed
      $client_called_back = true
      $client_cert_value = get_peer_cert
      $client_cipher_bits = get_cipher_bits
      $client_cipher_name = get_cipher_name
      $client_cipher_protocol = get_cipher_protocol
      EM.stop_event_loop
    end
  end

  def test_ssl_methods
    omit_unless(EM.ssl?)
    omit_if(rbx?)
    $server_called_back, $client_called_back = false, false
    $server_cert_value, $client_cert_value = nil, nil
    $server_cipher_bits, $client_cipher_bits = nil, nil
    $server_cipher_name, $client_cipher_name = nil, nil
    $server_cipher_protocol, $client_cipher_protocol = nil, nil

    EM.run {
      EM.start_server("127.0.0.1", 9999, ServerHandler)
      EM.connect("127.0.0.1", 9999, ClientHandler)
    }

    assert($server_called_back)
    assert($client_called_back)

    assert($server_cert_value.is_a?(NilClass))
    assert($client_cert_value.is_a?(String))

    assert($client_cipher_bits > 0)
    assert_equal($client_cipher_bits, $server_cipher_bits)

    assert($client_cipher_name.length > 0)
    assert_match(/AES/, $client_cipher_name)
    assert_equal($client_cipher_name, $server_cipher_name)

    assert_match(/TLS/, $client_cipher_protocol)
    assert_equal($client_cipher_protocol, $server_cipher_protocol)
  end

end
