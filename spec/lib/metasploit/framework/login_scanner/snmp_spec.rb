require 'spec_helper'
require 'metasploit/framework/login_scanner/snmp'

describe Metasploit::Framework::LoginScanner::SNMP do
  let(:public) { 'public' }
  let(:private) { nil }

  let(:pub_comm) {
    Metasploit::Framework::Credential.new(
        paired: false,
        public: public,
        private: private
    )
  }

  let(:invalid_detail) {
    Metasploit::Framework::Credential.new(
        paired: true,
        public: nil,
        private: nil
    )
  }

  let(:detail_group) {
    [ pub_comm ]
  }

  subject(:snmp_scanner) {
    described_class.new
  }

  it_behaves_like 'Metasploit::Framework::LoginScanner::Base',  has_realm_key: false, has_default_realm: false


  context '#attempt_login' do
    before(:each) do
      snmp_scanner.host = '127.0.0.1'
      snmp_scanner.port = 161
      snmp_scanner.connection_timeout = 1
      snmp_scanner.stop_on_success = true
      snmp_scanner.cred_details = detail_group
    end

    it 'creates a Timeout based on the connection_timeout' do
      ::Timeout.should_receive(:timeout).at_least(:once).with(snmp_scanner.connection_timeout)
      snmp_scanner.attempt_login(pub_comm)
    end

    it 'creates a SNMP Manager for each supported version of SNMP' do
      ::SNMP::Manager.should_receive(:new).twice.and_call_original
      snmp_scanner.attempt_login(pub_comm)
    end

  end

end
