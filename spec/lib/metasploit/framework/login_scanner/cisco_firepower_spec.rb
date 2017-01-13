require 'metasploit/framework/login_scanner/cisco_firepower'

RSpec.describe Metasploit::Framework::LoginScanner::CiscoFirepower do

    it_behaves_like 'Metasploit::Framework::LoginScanner::Base',  has_realm_key: true, has_default_realm: false
    it_behaves_like 'Metasploit::Framework::LoginScanner::RexSocket'

end
