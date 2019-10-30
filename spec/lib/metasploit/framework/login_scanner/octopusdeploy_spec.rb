require 'spec_helper'
require 'metasploit/framework/login_scanner/octopusdeploy'

RSpec.describe Metasploit::Framework::LoginScanner::OctopusDeploy do

    it_behaves_like 'Metasploit::Framework::LoginScanner::Base',  has_realm_key: true, has_default_realm: false
    it_behaves_like 'Metasploit::Framework::LoginScanner::RexSocket'
    it_behaves_like 'Metasploit::Framework::LoginScanner::HTTP'

end
