require 'spec_helper'
require 'metasploit/framework/login_scanner/telnet'

describe Metasploit::Framework::LoginScanner::Telnet do

  subject(:login_scanner) { described_class.new }

  it_behaves_like 'Metasploit::Framework::LoginScanner::Base'
  it_behaves_like 'Metasploit::Framework::LoginScanner::RexSocket'

  it { should respond_to :banner_timeout }
  it { should respond_to :telnet_timeout }

end