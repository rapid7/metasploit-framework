require 'spec_helper'
require 'metasploit/framework/login_scanner/mssql'

describe Metasploit::Framework::LoginScanner::MSSQL do

  subject(:login_scanner) { described_class.new }

  it_behaves_like 'Metasploit::Framework::LoginScanner::Base'
  it_behaves_like 'Metasploit::Framework::LoginScanner::RexSocket'
  it_behaves_like 'Metasploit::Framework::LoginScanner::NTLM'

end