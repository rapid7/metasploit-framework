
require 'spec_helper'
require 'metasploit/framework/login_scanner/http'

describe Metasploit::Framework::LoginScanner::HTTP do

  it_behaves_like 'Metasploit::Framework::LoginScanner::Base', false
  it_behaves_like 'Metasploit::Framework::LoginScanner::RexSocket'
  it_behaves_like 'Metasploit::Framework::LoginScanner::HTTP'

end
