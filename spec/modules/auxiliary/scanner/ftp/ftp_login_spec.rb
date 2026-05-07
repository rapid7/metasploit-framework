require 'rspec'

RSpec.describe 'FTP Login Scanner' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject do
    load_and_create_module(
      module_type: 'auxiliary',
      reference_name: 'scanner/ftp/ftp_login'
    )
  end

  let(:ip) { '127.0.0.1' }

  describe '#check_host' do
    before(:each) do
      allow(subject).to receive(:connect)
      allow(subject).to receive(:disconnect)
      allow(subject).to receive(:report_ftp_service_and_banner)
      allow(subject).to receive(:rport).and_return(21)
    end

    context 'when an FTP banner is present' do
      before(:each) do
        allow(subject).to receive(:banner).and_return('220 vsftpd 3.0.3')
        allow(subject).to receive(:banner_version).and_return('vsftpd 3.0.3')
      end

      it 'returns CheckCode::Appears' do
        expect(subject.check_host(ip).code).to eq 'appears'
      end

      it 'includes the banner version in the message' do
        expect(subject.check_host(ip).reason).to include('vsftpd 3.0.3')
      end

      it 'reports the FTP service and banner' do
        expect(subject).to receive(:report_ftp_service_and_banner).with(ip)
        subject.check_host(ip)
      end
    end

    context 'when a 120 banner is present' do
      before(:each) do
        allow(subject).to receive(:banner).and_return('120 Service ready in 2 minutes')
        allow(subject).to receive(:banner_version).and_return('Service ready in 2 minutes')
      end

      it 'returns CheckCode::Appears' do
        expect(subject.check_host(ip).code).to eq 'appears'
      end
    end

    context 'when the banner is nil' do
      before(:each) do
        allow(subject).to receive(:banner).and_return(nil)
      end

      it 'returns CheckCode::Unknown' do
        expect(subject.check_host(ip).code).to eq 'unknown'
      end

      it 'reports no valid banner' do
        expect(subject.check_host(ip).reason).to include('No valid FTP banner received')
      end
    end

    context 'when the banner does not match a valid FTP code' do
      before(:each) do
        allow(subject).to receive(:banner).and_return('500 Not FTP')
      end

      it 'returns CheckCode::Unknown' do
        expect(subject.check_host(ip).code).to eq 'unknown'
      end

      it 'reports no valid banner' do
        expect(subject.check_host(ip).reason).to include('No valid FTP banner received')
      end
    end

    context 'when the connection fails' do
      it 'returns CheckCode::Unknown for Rex::ConnectionError' do
        allow(subject).to receive(:connect).and_raise(Rex::ConnectionError)
        expect(subject.check_host(ip).code).to eq 'unknown'
      end

      it 'returns CheckCode::Unknown for Errno::ECONNRESET' do
        allow(subject).to receive(:connect).and_raise(Errno::ECONNRESET)
        expect(subject.check_host(ip).code).to eq 'unknown'
      end

      it 'reports port closed for Rex::ConnectionError' do
        allow(subject).to receive(:connect).and_raise(Rex::ConnectionError)
        expect(subject.check_host(ip).reason).to include('Port closed or connection refused')
      end
    end

    context 'when the connection times out' do
      it 'returns CheckCode::Unknown for Rex::ConnectionTimeout' do
        allow(subject).to receive(:connect).and_raise(Rex::ConnectionTimeout, 'timed out')
        expect(subject.check_host(ip).code).to eq 'unknown'
      end

      it 'returns CheckCode::Unknown for Timeout::Error' do
        allow(subject).to receive(:connect).and_raise(::Timeout::Error, 'timed out')
        expect(subject.check_host(ip).code).to eq 'unknown'
      end

      it 'returns CheckCode::Unknown for EOFError' do
        allow(subject).to receive(:connect).and_raise(::EOFError, 'end of file')
        expect(subject.check_host(ip).code).to eq 'unknown'
      end

      it 'includes the exception message' do
        allow(subject).to receive(:connect).and_raise(::Timeout::Error, 'timed out')
        expect(subject.check_host(ip).reason).to include('timed out')
      end
    end

    context 'disconnect behaviour' do
      it 'always calls disconnect on success' do
        allow(subject).to receive(:banner).and_return('220 FTP ready')
        allow(subject).to receive(:banner_version).and_return('FTP ready')
        expect(subject).to receive(:disconnect)
        subject.check_host(ip)
      end

      it 'always calls disconnect on connection failure' do
        allow(subject).to receive(:connect).and_raise(Rex::ConnectionError)
        expect(subject).to receive(:disconnect)
        subject.check_host(ip)
      end
    end
  end

  describe '#anonymous_creds' do
    it 'returns an empty array when ANONYMOUS_LOGIN is false' do
      subject.datastore['ANONYMOUS_LOGIN'] = false

      expect(subject.anonymous_creds).to eq([])
    end

    it 'returns the four anonymous browser credentials when ANONYMOUS_LOGIN is true' do
      subject.datastore['ANONYMOUS_LOGIN'] = true

      creds = subject.anonymous_creds

      expect(creds).to all(have_attributes(public: 'anonymous'))
      expect(creds.map(&:private)).to eq(['mozilla@example.com', 'IEUser@', 'User@', 'chrome@example.com'])
    end
  end

  describe '#test_ftp_access' do
    before(:each) do
      allow(subject).to receive(:rport).and_return(21)
    end

    it 'returns Read/Write when MKD succeeds' do
      allow(subject).to receive(:send_cmd).with(['MKD', anything], true).and_return('257 Directory created')
      allow(subject).to receive(:send_cmd).with(['RMD', anything], true).and_return('250 Directory removed')

      expect(subject.test_ftp_access(ip)).to eq('Read/Write')
    end

    it 'returns Read-only when MKD is rejected' do
      allow(subject).to receive(:send_cmd).with(['MKD', anything], true).and_return('550 Permission denied')

      expect(subject.test_ftp_access(ip)).to eq('Read-only')
    end

    it 'returns Read-only when MKD gets no response' do
      allow(subject).to receive(:send_cmd).with(['MKD', anything], true).and_return(nil)

      expect(subject.test_ftp_access(ip)).to eq('Read-only')
    end
  end

  describe '#report_ftp_service_and_banner' do
    before(:each) do
      allow(subject).to receive(:rport).and_return(21)
    end

    context 'when a banner is present' do
      before(:each) do
        allow(subject).to receive(:banner).and_return('220 vsFTPd 3.0.3')
        allow(subject).to receive(:banner_version).and_return('vsFTPd 3.0.3')
      end

      it 'reports the service' do
        expect(subject).to receive(:report_service).with(hash_including(host: ip, port: 21, name: 'ftp'))

        subject.report_ftp_service_and_banner(ip)
      end

      it 'reports a banner note' do
        allow(subject).to receive(:report_service)

        expect(subject).to receive(:report_note).with(hash_including(type: 'ftp.banner'))

        subject.report_ftp_service_and_banner(ip)
      end
    end

    context 'when no banner is present' do
      before(:each) do
        allow(subject).to receive(:banner).and_return(nil)
      end

      it 'still reports the service with nil info' do
        expect(subject).to receive(:report_service).with(hash_including(info: nil))

        subject.report_ftp_service_and_banner(ip)
      end

      it 'does not report a banner note' do
        allow(subject).to receive(:report_service)

        expect(subject).not_to receive(:report_note)

        subject.report_ftp_service_and_banner(ip)
      end
    end
  end

  describe '#run_scanner' do
    let(:credential) { Metasploit::Framework::Credential.new(public: 'msfadmin', private: 'wrongpass', private_type: :password) }

    before(:each) do
      allow(subject).to receive(:rport).and_return(21)
      allow(subject).to receive(:fullname).and_return('auxiliary/scanner/ftp/ftp_login')
      allow(subject).to receive(:myworkspace_id).and_return(1)
      allow(subject).to receive(:invalidate_login)
      allow(subject).to receive(:report_ftp_service_and_banner)
      allow(subject).to receive(:report_host)
    end

    context 'on the first INCORRECT result' do
      let(:result) do
        Metasploit::Framework::LoginScanner::Result.new(credential: credential, status: Metasploit::Model::Login::Status::INCORRECT, proof: 'bad password')
      end
      let(:scanner) { instance_double(Metasploit::Framework::LoginScanner::FTP, banner: '220 vsFTPd 3.0.3') }

      before(:each) do
        allow(scanner).to receive(:scan!).and_yield(result)
      end

      it 'reports the service exactly once' do
        expect(subject).to receive(:report_ftp_service_and_banner).once

        subject.run_scanner(ip, scanner) { |*| }
      end
    end

    context 'on repeated INCORRECT results' do
      let(:result) do
        Metasploit::Framework::LoginScanner::Result.new(credential: credential, status: Metasploit::Model::Login::Status::INCORRECT, proof: 'bad password')
      end
      let(:scanner) { instance_double(Metasploit::Framework::LoginScanner::FTP, banner: '220 vsFTPd 3.0.3') }

      before(:each) do
        allow(scanner).to receive(:scan!).and_yield(result).and_yield(result)
      end

      it 'only reports the service once across multiple failed attempts' do
        expect(subject).to receive(:report_ftp_service_and_banner).once

        subject.run_scanner(ip, scanner) { |*| }
      end
    end

    context 'on UNABLE_TO_CONNECT with proof present' do
      let(:result) do
        Metasploit::Framework::LoginScanner::Result.new(credential: credential, status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: 'connection refused')
      end
      let(:scanner) { instance_double(Metasploit::Framework::LoginScanner::FTP, banner: nil) }

      before(:each) do
        allow(scanner).to receive(:scan!).and_yield(result)
      end

      it 'reports the host' do
        expect(subject).to receive(:report_host).with(host: ip)

        subject.run_scanner(ip, scanner) { |*| }
      end
    end

    context 'on UNABLE_TO_CONNECT with no proof' do
      let(:result) do
        Metasploit::Framework::LoginScanner::Result.new(credential: credential, status: Metasploit::Model::Login::Status::UNABLE_TO_CONNECT, proof: nil)
      end
      let(:scanner) { instance_double(Metasploit::Framework::LoginScanner::FTP, banner: nil) }

      before(:each) do
        allow(scanner).to receive(:scan!).and_yield(result)
      end

      it 'does not report the host' do
        expect(subject).not_to receive(:report_host)

        subject.run_scanner(ip, scanner) { |*| }
      end
    end

    context 'on a SUCCESSFUL result' do
      let(:credential) { Metasploit::Framework::Credential.new(public: 'msfadmin', private: 'msfadmin', private_type: :password) }
      let(:result) do
        Metasploit::Framework::LoginScanner::Result.new(credential: credential, status: Metasploit::Model::Login::Status::SUCCESSFUL, proof: 'ok')
      end
      let(:scanner) { instance_double(Metasploit::Framework::LoginScanner::FTP, banner: '220 vsFTPd 3.0.3') }

      before(:each) do
        allow(scanner).to receive(:scan!).and_yield(result)
      end

      it 'yields the result and credential data to the given block' do
        expect { |b| subject.run_scanner(ip, scanner, &b) }.to yield_control
      end

      it 'reports the service' do
        expect(subject).to receive(:report_ftp_service_and_banner).with(ip)

        subject.run_scanner(ip, scanner) { |*| }
      end
    end
  end

  describe '#run_host' do
    let(:credential) { Metasploit::Framework::Credential.new(public: 'msfadmin', private: 'msfadmin', private_type: :password) }
    let(:result) do
      Metasploit::Framework::LoginScanner::Result.new(
        credential: credential,
        status: Metasploit::Model::Login::Status::SUCCESSFUL,
        proof: 'ok',
        host: ip,
        port: 21,
        protocol: 'tcp',
        service_name: 'ftp'
      )
    end
    let(:scanner) { instance_double(Metasploit::Framework::LoginScanner::FTP, banner: '220 vsFTPd 3.0.3') }

    before(:each) do
      allow(subject).to receive(:rport).and_return(21)
      allow(Metasploit::Framework::LoginScanner::FTP).to receive(:new).and_return(scanner)
      allow(scanner).to receive(:scan!).and_yield(result)

      allow(subject).to receive(:create_credential).and_return(double('credential_core'))
      allow(subject).to receive(:create_credential_login)
      allow(subject).to receive(:invalidate_login)
      allow(subject).to receive(:report_ftp_service_and_banner)
      allow(subject).to receive(:report_host)

      allow(subject).to receive(:connect)
      allow(subject).to receive(:disconnect)
      allow(subject).to receive(:send_user)
      allow(subject).to receive(:send_pass).and_return('230 Login successful')

      subject.datastore['USERNAME'] = 'msfadmin'
      subject.datastore['PASSWORD'] = 'msfadmin'
    end

    context 'when no credentials are specified' do
      before(:each) do
        subject.datastore['USERNAME'] = nil
        subject.datastore['PASSWORD'] = nil
        subject.datastore['ANONYMOUS_LOGIN'] = false
      end

      it 'does not instantiate a scanner' do
        expect(Metasploit::Framework::LoginScanner::FTP).not_to receive(:new)

        subject.run_host(ip)
      end
    end

    context 'with no post-auth checks enabled' do
      it 'creates a credential login record' do
        expect(subject).to receive(:create_credential_login)

        subject.run_host(ip)
      end

      it 'does not open a second connection' do
        expect(subject).not_to receive(:connect)

        subject.run_host(ip)
      end
    end

    context 'when CHECK_ACCESS is enabled' do
      before(:each) do
        subject.datastore['CHECK_ACCESS'] = true
        allow(subject).to receive(:send_cmd).and_return('257 Directory created')
      end

      it 'opens a second connection and authenticates as the found credential' do
        expect(subject).to receive(:connect).with(true, false)
        expect(subject).to receive(:send_user).with('msfadmin')

        subject.run_host(ip)
      end

      it 'records the access level on the credential login' do
        expect(subject).to receive(:create_credential_login).with(hash_including(access_level: 'Read/Write'))

        subject.run_host(ip)
      end

      it 'always disconnects the second connection' do
        expect(subject).to receive(:disconnect)

        subject.run_host(ip)
      end
    end

    context 'when DIRECTORY_LISTING is enabled' do
      before(:each) do
        subject.datastore['DIRECTORY_LISTING'] = true
        allow(subject).to receive(:ftp_list_directory)
      end

      it 'calls ftp_list_directory with the authenticated username' do
        expect(subject).to receive(:ftp_list_directory).with(logged_in_as: 'msfadmin', save_loot: true)

        subject.run_host(ip)
      end

      it 'still records the credential login' do
        expect(subject).to receive(:create_credential_login)

        subject.run_host(ip)
      end
    end

    context 'when EXTENDED_CHECKS is enabled' do
      before(:each) do
        subject.datastore['EXTENDED_CHECKS'] = true
        allow(subject).to receive(:ftp_fingerprint)
      end

      it 'calls ftp_fingerprint with the authenticated username' do
        expect(subject).to receive(:ftp_fingerprint).with(logged_in_as: 'msfadmin')

        subject.run_host(ip)
      end

      it 'still records the credential login' do
        expect(subject).to receive(:create_credential_login)

        subject.run_host(ip)
      end
    end

    context 'when CHECK_ACCESS, DIRECTORY_LISTING, and EXTENDED_CHECKS are all enabled' do
      before(:each) do
        subject.datastore['CHECK_ACCESS'] = true
        subject.datastore['DIRECTORY_LISTING'] = true
        subject.datastore['EXTENDED_CHECKS'] = true

        allow(subject).to receive(:send_cmd).and_return('257 Directory created')
        allow(subject).to receive(:ftp_list_directory)
        allow(subject).to receive(:ftp_fingerprint)
      end

      it 'runs all three post-auth checks and still records the credential' do
        expect(subject).to receive(:ftp_list_directory).with(logged_in_as: 'msfadmin', save_loot: true)
        expect(subject).to receive(:ftp_fingerprint).with(logged_in_as: 'msfadmin')
        expect(subject).to receive(:create_credential_login)

        subject.run_host(ip)
      end
    end

    context 'when a post-auth check raises a rescuable network error' do
      before(:each) do
        subject.datastore['DIRECTORY_LISTING'] = true
        allow(subject).to receive(:ftp_list_directory).and_raise(Errno::ECONNRESET)
      end

      it 'still disconnects and still records the credential login' do
        expect(subject).to receive(:disconnect)
        expect(subject).to receive(:create_credential_login)

        subject.run_host(ip)
      end
    end
  end
end
