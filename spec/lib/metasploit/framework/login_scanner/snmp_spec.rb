require 'spec_helper'
require 'metasploit/framework/login_scanner/snmp'

RSpec.describe Metasploit::Framework::LoginScanner::SNMP do
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

end
