require 'rspec'
require 'metasploit/framework/login_scanner/ssh'

RSpec.describe 'SSH Login Check Scanner' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject do
    load_and_create_module(
      module_type: 'auxiliary',
      reference_name: 'scanner/ssh/ssh_login'
    )
  end

  describe '#rport' do
    it 'returns the defined RPORT option' do
      subject.options.add_options([Msf::Opt::RPORT(99)])
      subject.import_defaults(false)

      expect(subject.rport).to eql 99
    end
  end

  describe '#session_setup' do
    let(:credential) do
      Metasploit::Framework::Credential.new(private: password, public: username)
    end
    let(:datastore) { Msf::ModuleDataStoreWithFallbacks.new(subject) }
    let(:host) { '10.10.10.10' }
    let(:module_manager) { instance_double(Msf::ModuleManager) }
    let(:password) { 'secret' }
    let(:platform) { 'unifi' }
    let(:proof) { 'this is the proof' }
    let(:result) do
      Metasploit::Framework::LoginScanner::Result.new(
        credential: credential,
        proof: proof
      )
    end
    let(:scanner) do
      instance_double(
        Metasploit::Framework::LoginScanner::SSH,
        ssh_socket: ssh_session,
        get_platform: platform,
        host: host
      )
    end
    let(:session_manager) do
      instance_double(Msf::SessionManager, register: nil)
    end
    let(:ssh_command_shell_bind) do
      instance_double(
        Msf::Sessions::SshCommandShellBind,
        alive: true,
        arch: nil,
        exploit_datastore: datastore,
        exploit_task: nil,
        exploit_uuid: nil,
        info: nil,
        platform: platform,
        register?: true,
        rstream: ssh_commandstream,
        session_host: host,
        session_port: nil,
        set_from_exploit: nil,
        sid: nil,
        tunnel_peer: nil,
        type: nil,
        username: nil,
        uuid: nil,
        via_exploit: nil,
        via_payload: nil,
        workspace: 'default'
      ).as_null_object.tap do |mock|
        allow(mock).to receive(:kind_of?) { |args| args == Msf::Session }
      end
    end
    let(:ssh_commandstream) { instance_double(Net::SSH::CommandStream) }
    let(:ssh_session) do
      instance_double(Net::SSH::Connection::Session, transport: transport_session)
    end
    let(:socket) do
      double(Object)
    end
    let(:transport_session) do
      instance_double(Net::SSH::Transport::Session).tap do |mock|
        allow(mock).to receive(:socket).and_return(socket)
      end
    end
    let(:username) { 'root' }

    before(:each) do
      allow(Msf::Sessions::SshCommandShellBind).to receive(:new).and_return(ssh_command_shell_bind)
      # This is mocked as SessionManager appears to be directly or indirectly triggering the
      # error for too many threads
      allow(subject.framework).to receive(:sessions).and_return(session_manager)
    end

    it 'requests the platform from the scanner' do
      expect(scanner).to receive(:get_platform).with(proof)

      subject.session_setup(result, scanner)
    end

    it 'instantiates a SshCommandShellBind instance' do
      expect(Msf::Sessions::SshCommandShellBind).to receive(:new).with(ssh_session)

      subject.session_setup(result, scanner)
    end

    it 'configures the SshCommandShellBind instance' do
      expect(ssh_command_shell_bind).to receive(:set_from_exploit).with(subject)

      subject.session_setup(result, scanner)
    end

    it 'updates the exploit datastore for the session' do
      subject.session_setup(result, scanner)

      expect(datastore.search_for('USERNAME').value).to eql username
      expect(datastore.search_for('PASSWORD').value).to eql password
    end

    it 'deletes the ssh session from the collection of sockets' do
      subject.add_socket(ssh_commandstream)

      subject.session_setup(result, scanner)

      expect(subject.send(:sockets)).to be_empty
    end

    it 'registers the session' do
      expect(session_manager).to receive(:register).with(ssh_command_shell_bind)

      subject.session_setup(result, scanner)
    end

    it 'passes module datastore to bootstrap method of the SshCommandShellBind instance' do
      expect(ssh_command_shell_bind).to receive(:bootstrap).with(subject.datastore)

      subject.session_setup(result, scanner)
    end

    it 'processes any autoruns defined for the module' do
      expect(ssh_command_shell_bind).to receive(:process_autoruns).with(subject.datastore)

      subject.session_setup(result, scanner)
    end

    it 'registers the session open event' do
      expect(ssh_command_shell_bind).to receive(:db_record=).with(an_instance_of(Mdm::Session))

      subject.session_setup(result, scanner)
    end

    it 'deletes the ssh transport socket from the collection of sockets' do
      subject.add_socket(socket)

      subject.session_setup(result, scanner)

      expect(subject.send(:sockets)).to be_empty
    end

    it 'sets the platform on the SshCommandShellBind instance' do
      expect(ssh_command_shell_bind).to receive(:platform=).with(platform)

      subject.session_setup(result, scanner)
    end

    it 'returns a SshCommandShellBind instance' do
      expect(subject.session_setup(result, scanner)).to eql ssh_command_shell_bind
    end

    it 'reports the host' do
      expect do
        subject.session_setup(result, scanner)
      end.to change(Mdm::Host, :count).by(1)

      expect(Mdm::Host.last.os_name).to eql platform
    end

    context 'when scanner does not have an ssh connection' do
      before(:each) do
        allow(scanner).to receive(:ssh_socket).and_return(nil)
      end

      it 'returns nil' do
        expect(subject.session_setup(result, scanner)).to be_nil
      end
    end

    context 'when the scanner platform is set to `unknown`' do
      let(:platform) { 'unknown' }

      it 'does not set the os_name for the Host record' do
        subject.session_setup(result, scanner)

        expect(Mdm::Host.last.os_name).to be_nil
      end
    end
  end
end
