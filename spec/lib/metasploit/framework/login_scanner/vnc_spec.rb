require 'spec_helper'
require 'metasploit/framework/login_scanner/vnc'

describe Metasploit::Framework::LoginScanner::VNC do

  subject(:login_scanner) { described_class.new }

  it_behaves_like 'Metasploit::Framework::LoginScanner::Base'
  it_behaves_like 'Metasploit::Framework::LoginScanner::RexSocket'

end