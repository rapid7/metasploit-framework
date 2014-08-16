require 'spec_helper'
require 'metasploit/framework/login_scanner'
require 'metasploit/framework/login_scanner/http'
require 'metasploit/framework/login_scanner/smb'
require 'metasploit/framework/login_scanner/vnc'

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
      it { should_not include Metasploit::Framework::LoginScanner::VNC }
    end
  end

  context "with name 'http'" do
    let(:name) { 'http' }

    it { should include Metasploit::Framework::LoginScanner::HTTP }
    it { should_not include Metasploit::Framework::LoginScanner::SMB }
    it { should_not include Metasploit::Framework::LoginScanner::VNC }
  end

  [ 80, 8080, 8000, 443 ].each do |foo|
    context "with port #{foo}" do
      let(:port) { foo }

      it { should include Metasploit::Framework::LoginScanner::HTTP }
      it { should include Metasploit::Framework::LoginScanner::Axis2 }
      it { should include Metasploit::Framework::LoginScanner::Tomcat }
      it { should_not include Metasploit::Framework::LoginScanner::SMB }
    end
  end

end
