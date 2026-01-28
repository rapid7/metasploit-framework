require 'spec_helper'
require 'metasploit/framework/login_scanner'
require 'metasploit/framework/login_scanner/http'
require 'metasploit/framework/login_scanner/smb'
require 'metasploit/framework/login_scanner/vnc'

RSpec.describe Metasploit::Framework::LoginScanner do

  describe '.classes_for_service' do
    subject { described_class.classes_for_service(service) }
    let(:port) { nil }
    let(:name) { nil }

    let(:service) do
      instance_double(Mdm::Service, port: port, name: name)
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

  describe '.all_http_classes' do
    let(:http_classes) { described_class.all_http_classes }

    it 'returns a populated array' do
      expect(http_classes).to be_a Array
      expect(http_classes).to_not be_empty
    end

    it 'includes HTTP classes' do
      expect(http_classes).to include Metasploit::Framework::LoginScanner::TeamCity
      expect(http_classes).to include Metasploit::Framework::LoginScanner::Ivanti
    end

    it 'does not include non-HTTP classes' do
      # Base HTTP scanner should not be present
      expect(http_classes).to_not include Metasploit::Framework::LoginScanner::HTTP
      expect(http_classes).to_not include Metasploit::Framework::LoginScanner::SMB
      expect(http_classes).to_not include Metasploit::Framework::LoginScanner::VNC
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

    it 'returns a list of valid services' do
      all_scanners = service_names.flat_map do |service_name|
        service = instance_double Mdm::Service, name: service_name, port: nil
        classes = described_class.classes_for_service(service)
        expect(classes).to_not be_empty
        classes
      end.uniq
      expect(all_scanners).to_not be_empty

      all_scanners.each do |scanner|
        # Emulate how Pro will initialize the class by passing a single configuration hash argument
        options = {
          bruteforce_speed: 5,
          host: '192.0.2.1',
          port: 1234,
          stop_on_success: true
        }
        aggregate_failures "#{scanner} is a valid scanner" do
          expect { scanner.new(options) }.to_not raise_error, "for #{scanner}"
          expect(scanner.const_defined?(:PRIVATE_TYPES)).to be(true), "for #{scanner}"
          expect(scanner.const_defined?(:LIKELY_SERVICE_NAMES)).to be(true), "for #{scanner}"
          expect(scanner.const_defined?(:LIKELY_PORTS)).to be(true), "for #{scanner}"
          if scanner.ancestors.include?(Metasploit::Framework::LoginScanner::HTTP) && scanner != Metasploit::Framework::LoginScanner::WinRM
            expect(scanner::LIKELY_SERVICE_NAMES).to include('http', 'https'), "for #{scanner}"
            expect(scanner::LIKELY_PORTS).to include(80, 443, 8000, 8080), "for #{scanner}"

            subject = scanner.new(options)
            # Ensure no network calls are made
            allow(subject).to receive(:send_request).and_return(nil)
            allow_any_instance_of(Rex::Proto::Http::Client).to receive(:request_cgi).and_return(nil)
            allow_any_instance_of(Rex::Proto::Http::Client).to receive(:_send_recv).and_return(nil)
            check_setup_result, elapsed_time = Rex::Stopwatch.elapsed_time do
              subject.check_setup
            end

            expect(check_setup_result).to be_a(String), "The check_setup API should return a string when it is not successful, and false when it is valid to run. Instead found: #{check_setup_result.inspect}"
            expect(elapsed_time).to be < 1.second, "This test took longer than expected (#{elapsed_time} seconds), suggesting that additional network mocking is required"
          end
        end
      end
    end
  end
end
