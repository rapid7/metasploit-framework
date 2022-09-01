require 'spec_helper'
require 'metasploit/framework/login_scanner'
require 'metasploit/framework/login_scanner/http'
require 'metasploit/framework/login_scanner/smb'
require 'metasploit/framework/login_scanner/vnc'

RSpec.describe Metasploit::Framework::LoginScanner do

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

    it { is_expected.to include Metasploit::Framework::LoginScanner::SMB }
    it { is_expected.not_to include Metasploit::Framework::LoginScanner::HTTP }
  end


  context "with port 445" do
    let(:port) { 445 }

    it { is_expected.to include Metasploit::Framework::LoginScanner::SMB }
    it { is_expected.not_to include Metasploit::Framework::LoginScanner::HTTP }
    it { is_expected.not_to include Metasploit::Framework::LoginScanner::VNC }
  end


  context "with name 'http'" do
    let(:name) { 'http' }

    it { is_expected.to include Metasploit::Framework::LoginScanner::HTTP }
    it { is_expected.not_to include Metasploit::Framework::LoginScanner::SMB }
    it { is_expected.not_to include Metasploit::Framework::LoginScanner::VNC }
  end

  [ 80, 8080, 8000, 443 ].each do |foo|
    context "with port #{foo}" do
      let(:port) { foo }

      it { is_expected.to include Metasploit::Framework::LoginScanner::HTTP }
      it { is_expected.to include Metasploit::Framework::LoginScanner::Axis2 }
      it { is_expected.to include Metasploit::Framework::LoginScanner::Tomcat }
      it { is_expected.not_to include Metasploit::Framework::LoginScanner::SMB }
    end
  end

end
