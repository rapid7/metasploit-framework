require 'rspec'

require 'metasploit/framework/login_scanner/postgres'

RSpec.describe 'PostgreSQL Login Scanner' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) do
    load_and_create_module(
      module_type: 'auxiliary',
      reference_name: 'scanner/postgres/postgres_login'
    )
  end

  let(:host) { '127.0.0.1' }
  let(:port) { 9001 }
  let(:credential) do
    Metasploit::Framework::Credential.new(
      public: 'postgres',
      private: 'password',
      realm: 'template1'
    )
  end

  let(:scanner) do
    instance_double(Metasploit::Framework::LoginScanner::Postgres)
  end

  before do
    mod.datastore['RPORT'] = port
    mod.datastore['VERBOSE'] = true

    allow(Metasploit::Framework::LoginScanner::Postgres)
      .to receive(:new)
      .and_return(scanner)

    allow(mod).to receive(:build_credential_collection)
    allow(mod).to receive(:configure_login_scanner).and_return({})
    allow(mod).to receive(:myworkspace_id).and_return(1)
    allow(mod).to receive(:create_session?).and_return(false)
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

      it 'does not include the target prefix in the module message' do
        expect(mod).to receive(:print_good)
          .with("Login Successful: #{credential}")

        mod.run_host(host)
      end
    end

    context 'when authentication fails' do
      let(:result) do
        Metasploit::Framework::LoginScanner::Result.new(
          credential: credential,
          status: Metasploit::Model::Login::Status::INCORRECT,
          proof: 'Authentication failed'
        )
      end

      before do
        allow(scanner).to receive(:scan!).and_yield(result)
        allow(mod).to receive(:invalidate_login)
      end

      it 'does not include the target prefix in the module message' do
        expect(mod).to receive(:print_error)
          .with("LOGIN FAILED: #{credential} (#{result.status}: #{result.proof})")

        mod.run_host(host)
      end
    end
  end
end
