
require 'spec_helper'
require 'metasploit/framework/login_scanner/winrm'

describe Metasploit::Framework::LoginScanner::WinRM do

  subject(:winrm_scanner) { described_class.new }

  it_behaves_like 'Metasploit::Framework::LoginScanner::Base'
  it_behaves_like 'Metasploit::Framework::LoginScanner::RexSocket'

  it { should respond_to :uri }
  it { should respond_to :method }

  context "#method=" do
    it "should raise, warning that the :method can't be changed" do
      expect { winrm_scanner.method = "GET" }.to raise_error(RuntimeError)
      expect(winrm_scanner.method).to eq("POST")
    end
  end

end

