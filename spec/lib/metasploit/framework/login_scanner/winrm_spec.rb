
require 'spec_helper'
require 'metasploit/framework/login_scanner/winrm'

RSpec.describe Metasploit::Framework::LoginScanner::WinRM do

  it_behaves_like 'Metasploit::Framework::LoginScanner::Base',  has_realm_key: true, has_default_realm: true
  it_behaves_like 'Metasploit::Framework::LoginScanner::RexSocket'
  it_behaves_like 'Metasploit::Framework::LoginScanner::HTTP'

  context "#method=" do
    subject(:winrm_scanner) { described_class.new }

    it "should raise, warning that the :method can't be changed" do
      expect { winrm_scanner.method = "GET" }.to raise_error(RuntimeError)
      expect(winrm_scanner.method).to eq("POST")
    end
  end

end

