require 'em_test_helper'

class TestSslVerify < Test::Unit::TestCase
  def setup
    $dir = File.dirname(File.expand_path(__FILE__)) + '/'
    $cert_from_file = File.read($dir+'client.crt')
  end

  module ClientNoCert
    def connection_completed
      start_tls()
    end

    def ssl_handshake_completed
      $client_handshake_completed = true
      close_connection
    end

    def unbind
      EM.stop_event_loop
    end
  end

  module Client
    def connection_completed
      start_tls(:private_key_file => $dir+'client.key', :cert_chain_file => $dir+'client.crt')
    end

    def ssl_handshake_completed
      $client_handshake_completed = true
      close_connection
    end

    def unbind
      EM.stop_event_loop
    end
  end

  module AcceptServer
    def post_init
      start_tls(:verify_peer => true)
    end

    def ssl_verify_peer(cert)
      $cert_from_server = cert
      true
    end

    def ssl_handshake_completed
      $server_handshake_completed = true
    end
  end

  module DenyServer
    def post_init
      start_tls(:verify_peer => true)
    end

    def ssl_verify_peer(cert)
      $cert_from_server = cert
      # Do not accept the peer. This should now cause the connection to shut down without the SSL handshake being completed.
      false
    end

    def ssl_handshake_completed
      $server_handshake_completed = true
    end
  end

  module FailServerNoPeerCert
    def post_init
      start_tls(:verify_peer => true, :fail_if_no_peer_cert => true)
    end

    def ssl_verify_peer(cert)
      raise "Verify peer should not get called for a client without a certificate"
    end

    def ssl_handshake_completed
      $server_handshake_completed = true
    end
  end

  def test_fail_no_peer_cert
    omit_unless(EM.ssl?)
    omit_if(rbx?)

    $client_handshake_completed, $server_handshake_completed = false, false

    EM.run {
      EM.start_server("127.0.0.1", 16784, FailServerNoPeerCert)
      EM.connect("127.0.0.1", 16784, ClientNoCert)
    }

    assert(!$client_handshake_completed)
    assert(!$server_handshake_completed)
  end

  def test_accept_server
    omit_unless(EM.ssl?)
    omit_if(EM.library_type == :pure_ruby) # Server has a default cert chain
    omit_if(rbx?)
    $client_handshake_completed, $server_handshake_completed = false, false
    EM.run {
      EM.start_server("127.0.0.1", 16784, AcceptServer)
      EM.connect("127.0.0.1", 16784, Client).instance_variable_get("@signature")
    }

    assert_equal($cert_from_file, $cert_from_server)
    assert($client_handshake_completed)
    assert($server_handshake_completed)
  end

  def test_deny_server
    omit_unless(EM.ssl?)
    omit_if(EM.library_type == :pure_ruby) # Server has a default cert chain
    omit_if(rbx?)
    $client_handshake_completed, $server_handshake_completed = false, false
    EM.run {
      EM.start_server("127.0.0.1", 16784, DenyServer)
      EM.connect("127.0.0.1", 16784, Client)
    }

    assert_equal($cert_from_file, $cert_from_server)
    assert(!$client_handshake_completed)
    assert(!$server_handshake_completed)
  end
end
