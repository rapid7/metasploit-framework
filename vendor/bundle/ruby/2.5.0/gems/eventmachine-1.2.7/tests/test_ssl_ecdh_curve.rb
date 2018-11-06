require 'em_test_helper'

class TestSslEcdhCurve < Test::Unit::TestCase
  module Client
    def post_init
      start_tls
    end

    def ssl_handshake_completed
      $client_handshake_completed = true
      $client_cipher_name = get_cipher_name
      close_connection
    end

    def unbind
      EM.stop_event_loop
    end
  end

  module Server
    def post_init
      start_tls(:ecdh_curve => "prime256v1", :cipher_list => "ECDH")
    end

    def ssl_handshake_completed
      $server_handshake_completed = true
      $server_cipher_name = get_cipher_name
    end
  end

  module NoCurveServer
    def post_init
      start_tls(:cipher_list => "ECDH")
    end

    def ssl_handshake_completed
      $server_handshake_completed = true
      $server_cipher_name = get_cipher_name
    end
  end

  def test_no_ecdh_curve
    omit_unless(EM.ssl?)
    omit_if(rbx?)

    $client_handshake_completed, $server_handshake_completed = false, false

    EM.run {
      EM.start_server("127.0.0.1", 16784, NoCurveServer)
      EM.connect("127.0.0.1", 16784, Client)
    }

    assert(!$client_handshake_completed)
    assert(!$server_handshake_completed)
  end

  def test_ecdh_curve
    omit_unless(EM.ssl?)
    omit_if(EM.library_type == :pure_ruby && RUBY_VERSION < "2.3.0")
    omit_if(rbx?)

    $client_handshake_completed, $server_handshake_completed = false, false
    $server_cipher_name, $client_cipher_name = nil, nil

    EM.run {
      EM.start_server("127.0.0.1", 16784, Server)
      EM.connect("127.0.0.1", 16784, Client)
    }

    assert($client_handshake_completed)
    assert($server_handshake_completed)

    assert($client_cipher_name.length > 0)
    assert_equal($client_cipher_name, $server_cipher_name)

    assert_match(/^(AECDH|ECDHE)/, $client_cipher_name)
  end


end
