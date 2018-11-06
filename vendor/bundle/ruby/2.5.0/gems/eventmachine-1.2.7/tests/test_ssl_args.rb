require "test/unit"
require 'tempfile'

require 'em_test_helper'

module EM
  def self._set_mocks
    class <<self
      alias set_tls_parms_old set_tls_parms
      alias start_tls_old start_tls
      begin
        old, $VERBOSE = $VERBOSE, nil
        def set_tls_parms *args; end
        def start_tls *args; end
      ensure
        $VERBOSE = old
      end
    end
  end

  def self._clear_mocks
    class <<self
      begin
        old, $VERBOSE = $VERBOSE, nil
        alias set_tls_parms set_tls_parms_old
        alias start_tls start_tls_old
      ensure
        $VERBOSE = old
      end
    end
  end
end

  

class TestSslArgs < Test::Unit::TestCase
  def setup
    EM._set_mocks
  end
  
  def teardown
    EM._clear_mocks
  end
  
  def test_tls_params_file_doesnt_exist
    priv_file, cert_file = 'foo_priv_key', 'bar_cert_file'
    [priv_file, cert_file].all? do |f|
      assert(!File.exist?(f), "Cert file #{f} seems to exist, and should not for the tests")
    end
    
    # associate_callback_target is a pain! (build!)
    conn = EM::Connection.new('foo')
    
    assert_raises(EM::FileNotFoundException) do
      conn.start_tls(:private_key_file => priv_file)
    end
    assert_raises(EM::FileNotFoundException) do
      conn.start_tls(:cert_chain_file => cert_file)
    end
    assert_raises(EM::FileNotFoundException) do
      conn.start_tls(:private_key_file => priv_file, :cert_chain_file => cert_file)
    end
  end
  
  def test_tls_params_file_does_exist
    priv_file = Tempfile.new('em_test')
    cert_file = Tempfile.new('em_test')
    priv_file_path = priv_file.path
    cert_file_path = cert_file.path
    conn = EM::Connection.new('foo')
    params = {:private_key_file => priv_file_path, :cert_chain_file => cert_file_path}
    begin
      conn.start_tls params
    rescue Object
      assert(false, 'should not have raised an exception')
    end
  end
end if EM.ssl?
