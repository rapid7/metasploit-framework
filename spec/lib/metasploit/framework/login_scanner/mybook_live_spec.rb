require 'spec_helper'
require 'metasploit/framework/login_scanner/mybook_live'

RSpec.describe Metasploit::Framework::LoginScanner::MyBookLive do

    it_behaves_like 'Metasploit::Framework::LoginScanner::Base',  has_realm_key: true, has_default_realm: false
    it_behaves_like 'Metasploit::Framework::LoginScanner::RexSocket'
    it_behaves_like 'Metasploit::Framework::LoginScanner::HTTP'

    describe '#service_opts' do
      it 'reports the service as mybook-live' do
        expect(subject.service_opts).to include(name: 'mybook-live')
      end
    end

end
