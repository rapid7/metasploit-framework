
require 'spec_helper'
require 'metasploit/framework/login_scanner/afp'

describe Metasploit::Framework::LoginScanner::AFP do

  subject(:http_scanner) { described_class.new }

  it_behaves_like 'Metasploit::Framework::LoginScanner::Base'
  it_behaves_like 'Metasploit::Framework::LoginScanner::RexSocket'

  it { should respond_to :login_timeout }


end

