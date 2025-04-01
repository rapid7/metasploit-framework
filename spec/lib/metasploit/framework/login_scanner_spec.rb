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

  describe '.all_service_names' do
    let(:service_names) { described_class.all_service_names }

    it 'returns a set of service names' do
      expect(service_names).to be_a Set
    end

    it 'returns a populated set' do
      expect(service_names).to_not be_empty
    end

    it 'includes common services names' do
      expect(service_names).to include 'http'
      expect(service_names).to include 'https'
      expect(service_names).to include 'smb'
    end
  end

  describe '.classes_for_service' do
    described_class.all_service_names.each do |service_name|
      context "with service #{service_name}" do
        let(:name) { service_name }
        let(:login_scanners) { described_class.classes_for_service(service) }

        it 'returns at least one class' do
          expect(login_scanners).to_not be_empty
        end


        MockService = Struct.new(:name, :port)

        described_class.classes_for_service(MockService.new(name: service_name)).each do |login_scanner|
          context "when the login scanner is #{login_scanner.name}" do
            it 'is a LoginScanner' do
              expect(login_scanner).to include Metasploit::Framework::LoginScanner::Base
            end

            it 'can be initialized with a single argument' do
              expect {
                # here we emulate how Pro will initialize the class by passing a single configuration hash argument
                login_scanner.new({
                  bruteforce_speed: 5,
                  host: '192.0.2.1',
                  port: 1234,
                  stop_on_success: true
                })
              }.to_not raise_error
            end
          end
        end
      end
    end
  end
end
