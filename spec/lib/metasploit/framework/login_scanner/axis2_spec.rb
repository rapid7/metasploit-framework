
require 'spec_helper'
require 'metasploit/framework/login_scanner/axis2'

RSpec.describe Metasploit::Framework::LoginScanner::Axis2 do

  it_behaves_like 'Metasploit::Framework::LoginScanner::Base',  has_realm_key: true, has_default_realm: false
  it_behaves_like 'Metasploit::Framework::LoginScanner::RexSocket'
  it_behaves_like 'Metasploit::Framework::LoginScanner::HTTP'

  context "#method=" do
    subject(:scanner) { described_class.new }

    it "should raise, warning that the :method can't be changed" do
      expect { scanner.method = "GET" }.to raise_error(RuntimeError)
      expect(scanner.method).to eq("POST")
    end
  end

end

