require 'spec_helper'
require 'metasploit/framework/login_scanner/pop3'

describe Metasploit::Framework::LoginScanner::POP3 do
  subject(:scanner) { described_class.new }

  it_behaves_like 'Metasploit::Framework::LoginScanner::Base'
  it_behaves_like 'Metasploit::Framework::LoginScanner::RexSocket'

  context "#attempt_login" do


  end
end
