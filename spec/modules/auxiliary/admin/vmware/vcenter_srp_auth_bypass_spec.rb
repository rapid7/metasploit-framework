require 'spec_helper'

RSpec.describe 'vCenter SRP authentication bypass' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) do
    load_and_create_module(module_type: 'auxiliary', reference_name: 'admin/vmware/vcenter_srp_auth_bypass')
  end

  let(:reference) { instance_double(Msf::Exploit::Remote::Vmdir::Client, socket: double('reference socket')) }
  let(:oracle) { instance_double(Msf::Exploit::Remote::Vmdir::Client, socket: double('oracle socket')) }
  let(:login) { instance_double(Msf::Exploit::Remote::Vmdir::Client, socket: double('login socket', peerinfo: '192.0.2.1:2012')) }
  let(:key) { 'K' * 20 }
  let(:first_handle) { "\x00" * 4 + Rex::Proto::DCERPC::UUID.uuid_pack('00000010-0000-1000-8000-000000000001') }
  let(:last_handle) { "\x00" * 4 + Rex::Proto::DCERPC::UUID.uuid_pack('00000030-0000-1000-8000-000000000001') }

  def response(code, value = nil)
    result = Rex::Proto::Http::Response.new(code)
    result.body = { value: value }.to_json
    result
  end

  before do
    mod.datastore['RHOSTS'] = '192.0.2.1'
    mod.datastore['AutoCheck'] = false
    mod.datastore['CreateSession'] = false
    allow(mod).to receive(:vmdir_connect).with(Msf::Exploit::Remote::Vmdir::SRP_INTERFACE).and_return(reference, oracle)
    allow(mod).to receive(:vmdir_connect).with(nil).and_return(login)
    allow(mod).to receive(:vmdir_disconnect)
    allow(mod).to receive(:report_service)
    allow(reference).to receive(:new_verifier).and_return(first_handle, last_handle)
    allow(reference).to receive(:delete_verifier)
    allow(oracle).to receive(:session_key).and_return(key)
  end

  it 'checks cross-association disclosure and removes its reference context' do
    expect(reference).to receive(:delete_verifier).with(first_handle)
    expect(mod.check).to eq(Msf::Exploit::CheckCode::Vulnerable)
  end

  it 'defaults to creating a session' do
    expect(mod.class.new.datastore['CreateSession']).to be(true)
  end

  it 'returns Unknown rather than Safe when key retrieval is inconclusive' do
    allow(oracle).to receive(:session_key).and_return(nil)
    expect(mod.check).to eq(Msf::Exploit::CheckCode::Unknown)
  end

  it 'returns Unknown and closes a partial setup when verifier creation fails' do
    allow(reference).to receive(:new_verifier).and_raise(Msf::Exploit::Remote::Vmdir::Error, 'Unknown principal')
    expect(mod).to receive(:vmdir_disconnect).with(reference)
    expect(mod).to receive(:vmdir_disconnect).with(oracle)
    expect(mod.check).to eq(Msf::Exploit::CheckCode::Unknown)
  end

  it 'reports the protected read, loot and validated principal against the identified service' do
    expect(mod).not_to receive(:start_session)
    service = instance_double(Mdm::Service)
    allow(mod).to receive(:report_service).and_return(service)
    allow(login).to receive(:challenge).and_yield.and_return({ salt: 'salt', server_b: 'challenge' })
    expect(login).to receive(:authenticate).with('administrator@vsphere.local', anything, key)
    allow(login).to receive(:directory_state).and_return(3)
    expect(mod).to receive(:store_loot).with(anything, 'application/json', '192.0.2.1', anything, 'vmdir_srp.json', anything, service).and_return('/tmp/evidence.json')
    expect(mod).to receive(:report_vuln).with(hash_including(service: service, host: '192.0.2.1', port: 2012))
    expect(mod).to receive(:create_credential_and_login).with(hash_including(username: 'administrator@vsphere.local', service_name: 'vmdir', status: Metasploit::Model::Login::Status::SUCCESSFUL, last_attempted_at: an_instance_of(Time)))
    expect(reference).to receive(:delete_verifier).with(first_handle)
    expect(reference).to receive(:delete_verifier).with(last_handle)
    mod.run
  end

  it 'transfers the authenticated socket to a registered session and still closes the other clients' do
    mod.datastore['CreateSession'] = true
    registered = instance_double(Msf::Sessions::Vmdir, sid: 7, type: 'vmdir')
    input = double('session input')
    output = Rex::Ui::Text::Output::Buffer.new
    allow(input).to receive(:dup).and_return(input)
    allow(mod).to receive(:user_input).and_return(input)
    allow(mod).to receive(:user_output).and_return(output)
    allow(login).to receive(:challenge).and_yield.and_return({ salt: 'salt', server_b: 'challenge' })
    allow(login).to receive(:authenticate)
    allow(login).to receive(:directory_state).and_return(3)
    allow(mod).to receive(:store_loot).and_return('/tmp/evidence.json')
    allow(mod).to receive(:report_vuln)
    allow(mod).to receive(:create_credential_and_login)
    expect(mod).to receive(:start_session).with(mod, anything, {}, false, login.socket, an_instance_of(Msf::Sessions::Vmdir)).and_return(registered)
    expect(mod).not_to receive(:vmdir_disconnect).with(login)
    expect(mod).to receive(:vmdir_disconnect).with(oracle).ordered
    expect(mod).to receive(:vmdir_disconnect).with(reference).ordered
    expect(registered).to receive(:interact).with(input, output).ordered
    mod.run
  end

  it 'stops at MaxGuesses and still releases every owned context and socket' do
    mod.datastore['MaxGuesses'] = 1
    allow(login).to receive(:challenge).and_yield.and_return({ salt: 'salt', server_b: 'challenge' })
    expect(oracle).to receive(:session_key).once.and_return(nil)
    expect(reference).to receive(:delete_verifier).with(first_handle)
    expect(reference).to receive(:delete_verifier).with(last_handle)
    expect(mod).to receive(:vmdir_disconnect).with(login)
    expect { mod.run }.to raise_error(Msf::Auxiliary::Failed, /inconclusive/)
  end

  it 'continues cleanup after a reference deletion fails' do
    allow(oracle).to receive(:session_key).and_raise(Msf::Exploit::Remote::Vmdir::Error, 'Rejected')
    allow(reference).to receive(:delete_verifier).and_raise(Msf::Exploit::Remote::Vmdir::Error, 'Cleanup rejected')
    expect(mod).to receive(:vmdir_disconnect).with(reference)
    expect(mod).to receive(:vmdir_disconnect).with(oracle)
    expect(mod.check).to eq(Msf::Exploit::CheckCode::Unknown)
  end

  it 'classifies an exhausted search time budget as an inconclusive timeout' do
    allow(login).to receive(:challenge).and_yield.and_return({ salt: 'salt', server_b: 'challenge' })
    allow(oracle).to receive(:session_key).and_raise(Timeout::Error)
    expect { mod.run }.to raise_error(Msf::Auxiliary::Failed, /inconclusive/)
    expect(mod.fail_reason).to eq(Msf::Module::Failure::TimeoutExpired)
  end

  it 'downloads the database and closes the owned RPC file context' do
    allow(login).to receive(:open_database).and_return('file handle')
    allow(login).to receive(:read_database).and_return('database bytes', '')
    expect(login).to receive(:close_database).with('file handle', 'administrator@vsphere.local', key)
    expect(mod).to receive(:store_loot).with('vmware.vmdir.database', 'application/octet-stream', '192.0.2.1', 'database bytes', 'data.mdb').and_return('/tmp/data.mdb')
    expect(mod.download_database(login, key)).to eq('/tmp/data.mdb')
  end

  it 'closes a database context after a read failure' do
    allow(login).to receive(:open_database).and_return('file handle')
    allow(login).to receive(:read_database).and_raise(Msf::Exploit::Remote::Vmdir::Error, 'Read failed')
    expect(login).to receive(:close_database)
    expect { mod.download_database(login, key) }.to raise_error(Msf::Exploit::Remote::Vmdir::Error, 'Read failed')
  end

  describe 'SHELL session selection' do
    let(:output) { Rex::Ui::Text::Output::Buffer.new }
    let(:password) { 'ABCDabcd1234!abcdefghijkl' }
    let(:credentials) do
      {
        key: instance_double(OpenSSL::PKey::RSA, to_pem: 'STS key'),
        certificate: instance_double(OpenSSL::X509::Certificate, to_pem: 'STS certificate'),
        ca_certificate: instance_double(OpenSSL::X509::Certificate, to_pem: 'VMCA certificate')
      }
    end

    before do
      mod.datastore['ACTION'] = 'SHELL'
      mod.init_ui(nil, output)
      allow(mod).to receive(:myworkspace_id).and_return(1)
      allow(mod).to receive(:download_database).with(login, key).and_return('/tmp/data.mdb')
      allow(mod).to receive(:vcenter_sts_credentials).with('/tmp/data.mdb').and_return(credentials)
      allow(mod).to receive(:store_loot).and_return('/tmp/recovery.json')
      allow(mod).to receive(:vcenter_hostname).and_return('vc.example.test')
      allow(mod).to receive(:vcenter_bearer_assertion).and_return('signed assertion')
      allow(mod).to receive(:vcenter_api_login).and_return('api-session')
      allow(mod).to receive(:appliance_value).with(anything, %w[access ssh]).and_return(false)
      allow(mod).to receive(:appliance_value).with(anything, %w[access shell]).and_return({ 'enabled' => false, 'timeout' => 0 })
      allow(mod).to receive(:appliance_request).and_return(response(200))
      allow(mod).to receive(:appliance_request).with(anything, 'GET', ['local-accounts', 'manual-user'], codes: [200, 404]).and_return(response(404))
      allow(mod).to receive(:create_credential_and_login)
      allow(mod).to receive(:restore_appliance)
      allow(mod).to receive(:logout_appliance)
      allow(Faker::Internet).to receive(:username).and_return('manual-user')
      allow(Faker::Name).to receive(:name).and_return('Manual Owner')
      allow(Rex::Text).to receive(:rand_text_alpha_upper).with(4).and_return('ABCD')
      allow(Rex::Text).to receive(:rand_text_alpha_lower).with(4).and_return('abcd')
      allow(Rex::Text).to receive(:rand_text_numeric).with(4).and_return('1234')
      allow(Rex::Text).to receive(:rand_text_alphanumeric).with(12).and_return('abcdefghijkl')
      allow(Rex::Text).to receive(:rand_text_alphanumeric).with(8).and_return('1234abcd')
    end

    it 'prints and retains the created credentials without attempting SSH or opening a session' do
      expect(mod).to receive(:appliance_request).with(
        anything, 'POST', ['local-accounts', 'manual-user'],
        data: { config: { password: password, full_name: 'Manual Owner 1234abcd', roles: ['superAdmin'], enabled: true, password_expires: false } }
      ).and_return(response(200))
      expect(mod).to receive(:create_credential_and_login).with(hash_including(username: 'manual-user', private_data: password, service_name: 'ssh', status: Metasploit::Model::Login::Status::UNTRIED))
      expect(mod).to receive(:appliance_request).with(anything, 'PUT', %w[access ssh], data: { enabled: true }).and_return(response(200))
      expect(mod).to receive(:appliance_request).with(anything, 'PUT', %w[access shell], data: { config: { enabled: true, timeout: 600 } }).and_return(response(200))
      expect(Net::SSH).not_to receive(:start)
      expect(mod).not_to receive(:vcenter_root_shell)
      expect(mod).not_to receive(:start_session)
      expect(mod).not_to receive(:restore_appliance)
      expect(mod).to receive(:logout_appliance).with(hash_including(session_id: 'api-session'))

      expect(mod.shell_session(login, key)).to be_nil
      expect(output.dump_buffer).to include("manual-user:#{password}")
    end

    it 'retains the account after partial provisioning when CreateSession is false' do
      allow(mod).to receive(:appliance_request).with(anything, 'PUT', %w[access shell], data: anything).and_raise(Msf::Exploit::Remote::HTTP::VmwareVcenter::Error, 'Bash configuration failed')
      expect(Net::SSH).not_to receive(:start)
      expect(mod).not_to receive(:restore_appliance)
      expect(mod).to receive(:logout_appliance)

      expect { mod.shell_session(login, key) }.to raise_error(Msf::Exploit::Remote::HTTP::VmwareVcenter::Error, 'Bash configuration failed')
    end

    it 'restores the account and access settings when provisioning fails with CreateSession true' do
      mod.datastore['CreateSession'] = true
      allow(mod).to receive(:appliance_request).with(anything, 'PUT', %w[access shell], data: anything).and_raise(Msf::Exploit::Remote::HTTP::VmwareVcenter::Error, 'Bash configuration failed')
      expect(Net::SSH).not_to receive(:start)
      expect(mod).to receive(:restore_appliance).with(hash_including(account: 'manual-user', account_attempted: true, ssh_attempted: true, shell_attempted: true))
      expect(mod).to receive(:logout_appliance)

      expect { mod.shell_session(login, key) }.to raise_error(Msf::Exploit::Remote::HTTP::VmwareVcenter::Error, 'Bash configuration failed')
      expect(output.dump_buffer).not_to include("manual-user:#{password}")
    end

    it 'opens and registers a root shell with deferred cleanup when CreateSession is true' do
      mod.datastore['CreateSession'] = true
      socket = double('SSH socket')
      transport = instance_double(Net::SSH::Transport::Session, socket: socket)
      ssh = instance_double(Net::SSH::Connection::Session, transport: transport)
      stream = double('SSH command stream')
      shell = instance_double(Msf::Sessions::Vmdir::Shell, rstream: stream)
      registered = instance_double(Msf::Sessions::Vmdir::Shell)
      cleanup = nil
      allow(mod).to receive(:sockets).and_return([socket])
      expect(Net::SSH).to receive(:start).with('192.0.2.1', 'manual-user', hash_including(port: 22, password: password, auth_methods: ['password'])).and_return(ssh)
      expect(mod).to receive(:vcenter_root_shell).with(ssh, username: 'manual-user', password: password, timeout: 30).and_return({ session: shell, proof: 'uid=0(root) gid=0(root)' })
      expect(shell).to receive(:after_close=) { |callback| cleanup = callback }
      expect(mod).to receive(:start_session).with(mod, anything, { 'USERNAME' => 'manual-user' }, false, stream, shell).and_return(registered)
      expect(shell).not_to receive(:cleanup)
      expect(mod).to receive(:logout_appliance)

      expect(mod.shell_session(login, key)).to eq(registered)
      expect(mod).not_to have_received(:restore_appliance)
      cleanup.call
      expect(mod).to have_received(:restore_appliance).with(hash_including(account: 'manual-user'))
    end
  end

  describe 'appliance recovery' do
    let(:context) do
      {
        host: '192.0.2.1', port: 443, principal: 'administrator@vsphere.local', hostname: 'vc.example.test', credentials: {},
        session_id: 'session-id', account: 'temporary-user', full_name: 'Temporary Owner 1234', account_attempted: true,
        ssh_enabled: false, shell_config: { 'enabled' => false, 'timeout' => 0 }, ssh_attempted: true, shell_attempted: true
      }
    end

    before do
      allow(mod).to receive(:logout_appliance)
      allow(mod).to receive(:appliance_request).with(context, 'PUT', %w[access shell], data: { config: context[:shell_config] }).and_return(response(200))
      allow(mod).to receive(:appliance_request).with(context, 'GET', %w[access shell]).and_return(response(200, context[:shell_config]))
      allow(mod).to receive(:appliance_request).with(context, 'PUT', %w[access ssh], data: { enabled: false }).and_return(response(200))
      allow(mod).to receive(:appliance_request).with(context, 'GET', %w[access ssh]).and_return(response(200, false))
      allow(mod).to receive(:appliance_request).with(context, 'GET', ['local-accounts', context[:account]], codes: [200, 404]).and_return(response(200, { 'fullname' => context[:full_name] }), response(404))
      allow(mod).to receive(:appliance_request).with(context, 'DELETE', ['local-accounts', context[:account]], codes: [200, 404, 500]).and_return(response(200))
    end

    it 'restores and reads back original settings before deleting its own account' do
      expect(mod).to receive(:appliance_request).with(context, 'DELETE', ['local-accounts', context[:account]], codes: [200, 404, 500]).and_return(response(200))
      mod.restore_appliance(context)
      expect(context[:restored]).to be(true)
    end

    it 'continues account deletion after an access setting cannot be restored' do
      allow(mod).to receive(:appliance_request).with(context, 'PUT', %w[access shell], data: anything).and_raise(Msf::Exploit::Remote::HTTP::VmwareVcenter::Error, 'API rejected Bash restoration')
      expect(mod).to receive(:appliance_request).with(context, 'DELETE', ['local-accounts', context[:account]], codes: [200, 404, 500]).and_return(response(200))
      mod.restore_appliance(context)
      expect(context[:restored]).to be(false)
    end

    it 'does not delete an account whose saved identity no longer matches' do
      allow(mod).to receive(:appliance_request).with(context, 'GET', ['local-accounts', context[:account]], codes: [200, 404]).and_return(response(200, { 'fullname' => 'Another Owner' }))
      expect(mod).not_to receive(:appliance_request).with(context, 'DELETE', anything, any_args)
      mod.restore_appliance(context)
      expect(context[:restored]).to be(false)
    end

    it 're-authenticates against the original target after the API session has ended' do
      context[:session_id] = nil
      mod.datastore['RHOSTS'] = '192.0.2.2'
      expect(mod).to receive(:vcenter_bearer_assertion).with({}, username: 'administrator@vsphere.local', hostname: 'vc.example.test').and_return('fresh assertion')
      expect(mod).to receive(:vcenter_api_login).with('fresh assertion', host: '192.0.2.1', port: 443).and_return('fresh-session-id')
      mod.restore_appliance(context)
      expect(context[:restored]).to be(true)
    end
  end
end
