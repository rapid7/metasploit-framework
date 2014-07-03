require 'spec_helper'
require 'metasploit/framework/login_scanner'

describe Metasploit::Framework::LoginScanner do

  subject { described_class.classes_for_service(service) }
  let(:port) { nil }
  let(:name) { nil }

  let(:service) do
    s = double('service')
    allow(s).to receive(:port) { port }
    allow(s).to receive(:name) { name }
    s
  end

  context "with name 'smb'" do
    let(:name) { 'smb' }

    it { should include Metasploit::Framework::LoginScanner::SMB }
    it { should_not include Metasploit::Framework::LoginScanner::HTTP }
  end

  [ 139, 445 ].each do |foo|
    context "with port #{foo}" do
      let(:port) { foo }

      it { should include Metasploit::Framework::LoginScanner::SMB }
      it { should_not include Metasploit::Framework::LoginScanner::HTTP }
    end
  end

end
