require 'rspec'
require 'metasploit/framework/login_scanner/mysql'

RSpec.describe 'MySQL Login Scanner' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) do
    load_and_create_module(
      module_type: 'auxiliary',
      reference_name: 'scanner/mysql/mysql_login'
    )
  end

  let(:host) { '127.0.0.1' }
  let(:port) { 3306 }
  let(:credential) do
    Metasploit::Framework::Credential.new(
      public: 'msftest',
      private: 'password'
    )
  end
  let(:scanner) do
    instance_double(Metasploit::Framework::LoginScanner::MySQL)
  end

  before do
    mod.datastore['RHOST'] = host
    mod.datastore['RPORT'] = port
    mod.datastore['VERBOSE'] = true

    allow(Metasploit::Framework::LoginScanner::MySQL)
      .to receive(:new).and_return(scanner)
    allow(mod).to receive(:mysql_version_check).and_return(true)
    allow(mod).to receive(:build_credential_collection)
    allow(mod).to receive(:configure_login_scanner).and_return({})
    allow(mod).to receive(:myworkspace_id).and_return(1)
    allow(mod).to receive(:create_session?).and_return(false)
  end

  describe '#vprint_error' do
    it 'prints exactly one target prefix when verbose error output is enabled' do
      message = 'Unsupported target version of MySQL detected. Skipping.'
      output = double('output', prompting?: false)
      allow(mod).to receive(:user_output).and_return(output)

      expect(output).to receive(:print_error)
        .with("#{host}:#{port}        - #{message}")

      mod.vprint_error(message)
    end

    it 'suppresses output when module and framework verbosity are disabled' do
      mod.datastore['VERBOSE'] = false
      allow(mod.framework.datastore).to receive(:[]).and_call_original
      allow(mod.framework.datastore).to receive(:[]).with('VERBOSE').and_return(false)

      expect(mod).not_to receive(:print_error)
      mod.vprint_error('Unsupported target version of MySQL detected. Skipping.')
    end
  end

  describe '#mysql_version_check' do
    it 'does not manually include the target prefix when version checking raises an error' do
      allow(mod).to receive(:mysql_version_check).and_call_original
      allow(mod).to receive(:connect).and_raise(RuntimeError, 'unexpected response')

      expect(mod).to receive(:vprint_error)
        .with('error checking version RuntimeError unexpected response')

      expect(mod.mysql_version_check).to be(false)
    end
  end

  describe 'unhandled login scanner errors' do
    it 'prints the target prefix exactly once in the warning' do
      output = double('output', prompting?: false)
      allow(mod).to receive(:user_output).and_return(output)

      allow(Metasploit::Framework::LoginScanner::MySQL)
        .to receive(:new).and_call_original

      scanner = Metasploit::Framework::LoginScanner::MySQL.new(
        framework: mod.framework,
        framework_module: mod,
        host: host,
        port: port,
        cred_details: [credential],
        connection_timeout: 1,
        stop_on_success: false
      )

      allow(scanner).to receive(:attempt_login)
        .and_raise(RuntimeError, 'unexpected scanner failure')

      expect(output).to receive(:print_warning) do |message|
        expect(message.scan(/#{Regexp.escape("#{host}:#{port}")}/).length).to eq(1)
        expect(message).to include('Unhandled error')
        expect(message).to include('unexpected scanner failure')
      end

      scanner.scan!
    end
  end

  describe '#run_host' do
    context 'when authentication succeeds' do
      let(:result) do
        Metasploit::Framework::LoginScanner::Result.new(
          credential: credential,
          status: Metasploit::Model::Login::Status::SUCCESSFUL
        )
      end

      before do
        allow(scanner).to receive(:scan!).and_yield(result)
        allow(mod).to receive(:create_credential).and_return(double)
        allow(mod).to receive(:create_credential_login)
      end

      it 'does not add a duplicate target prefix to successful authentication output' do
        expect(mod).to receive(:print_good)
          .with("Success: '#{credential}'")

        mod.run_host(host)
      end
    end

    context 'when authentication fails' do
      let(:result) do
        Metasploit::Framework::LoginScanner::Result.new(
          credential: credential,
          status: Metasploit::Model::Login::Status::INCORRECT,
          proof: 'Access denied'
        )
      end

      before do
        allow(scanner).to receive(:scan!).and_yield(result)
        allow(mod).to receive(:invalidate_login)
      end

      it 'uses verbose target-aware output for failed authentication' do
        expect(mod).to receive(:vprint_error)
          .with("LOGIN FAILED: #{credential} (#{result.status}: #{result.proof})")

        mod.run_host(host)
      end
    end

    context 'when the connection fails' do
      before do
        allow(mod).to receive(:mysql_version_check)
          .and_raise(Rex::ConnectionError, 'connection refused')
      end

      it 'does not include the target prefix in the module message' do
        expect(mod).to receive(:vprint_error)
          .with(a_string_starting_with('Unable to connect: '))

        mod.run_host(host)
      end
    end

    context 'when the target MySQL version is unsupported' do
      before do
        allow(mod).to receive(:mysql_version_check).and_return(false)
      end

      it 'does not include the target prefix in the module message' do
        expect(mod).to receive(:vprint_error)
          .with('Unsupported target version of MySQL detected. Skipping.')

        mod.run_host(host)
      end
    end
  end
end
