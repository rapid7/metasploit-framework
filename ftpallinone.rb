require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/ftp'

class Metasploit3 < Msf::Auxiliary
  include Msf::Exploit::Remote::Ftp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute

  def proto
    'ftp'
  end

  def initialize
    super(
      'Name'        => 'ftpSpecterSweep',
      'Description' => %q{
        This module, SpecterSweep, is a versatile FTP login scanner designed to test credentials on a
        variety of FTP servers. It conducts thorough login attempts across a range of target machines,
        identifying successful logins and providing detailed reports. SpecterSweep not only reports
        successful logins but also integrates seamlessly with database plugins,
        allowing for the recording of login data and host information,
        facilitating effective access tracking and management.
      },
      'Author'      => 'taha-ishaq',
      'References'  => [
        [ 'CVE', '1999-0502' ], # Weak password
        [ 'URL', 'https://example.com' ], # Add relevant URLs here
        # Add more references as needed
      ],
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(21),
        OptBool.new('Record_Guest', [ false, "Record anonymous/guest logins to the database", false ]),
        OptEnum.new('VERBOSE_LEVEL', [ false, 'Verbosity level', '1', ['1', '2', '3', '4'] ])
      ], self.class
    )
    register_advanced_options(
      [
        OptBool.new('SINGLE_SESSION', [ false, 'Disconnect after every login attempt', false])
      ]
    )

    deregister_options('FTPUSER','FTPPASS') # Can use these, but should use 'username' and 'password'
    @accepts_all_logins = {}
  end
  
  def verbose_level
    datastore['VERBOSE_LEVEL'].to_i
  end

  def verbose(msg, level = 1)
    return if level > verbose_level

    print_status("#{rhost}:#{rport} - #{msg}")
  end

  def run_host(ip)
    verbose("Starting FTP login sweep", 1)
    
    begin
      connect

      verbose("Connected to target FTP server", 1)

      cred_collection = Metasploit::Framework::CredentialCollection.new(
          blank_passwords: datastore['BLANK_PASSWORDS'],
          pass_file: datastore['PASS_FILE'],
          password: datastore['PASSWORD'],
          user_file: datastore['USER_FILE'],
          userpass_file: datastore['USERPASS_FILE'],
          username: datastore['USERNAME'],
          user_as_pass: datastore['USER_AS_PASS'],
          prepended_creds: anonymous_creds
      )

      scanner = Metasploit::Framework::LoginScanner::FTP.new(
        host: ip,
        port: rport,
        proxies: datastore['PROXIES'],
        cred_details: cred_collection,
        stop_on_success: datastore['STOP_ON_SUCCESS'],
        connection_timeout: 30
      )

      scanner.scan! do |result|
        credential_data = result.to_h
        credential_data.merge!(
            module_fullname: self.fullname,
            workspace_id: myworkspace_id
        )
        if result.success?
          credential_core = create_credential(credential_data)
          credential_data[:core] = credential_core
          create_credential_login(credential_data)
    
          print_good "#{ip}:#{rport} - LOGIN SUCCESSFUL: #{result.credential}"
        else
          invalidate_login(credential_data)
          print_status "#{ip}:#{rport} - LOGIN FAILED: #{result.credential} (#{result.status}: #{result.proof})"
        end
      end
    rescue ::Rex::ConnectionRefused, ::Rex::ConnectionError => e
      verbose("Connection error: #{e.class} - #{e.message}", 1)
    ensure
      disconnect
    end
  end

  def grab_banner(ip)
    connect
    banner = banner.to_s.strip
    disconnect
    banner.empty? ? nil : banner
  rescue ::Rex::ConnectionRefused, ::Rex::ConnectionError
    nil
  end

  def anonymous_creds
    anon_creds = []
    if datastore['RECORD_GUEST']
      ['IEUser@', 'User@', 'mozilla@example.com', 'chrome@example.com' ].each do |password|
        anon_creds << Metasploit::Framework::Credential.new(public: 'anonymous', private: password)
      end
    end
    anon_creds
  end

  def test_ftp_access(user,scanner)
    dir = Rex::Text.rand_text_alpha(8)
    write_check = scanner.send_cmd(['MKD', dir], true)
    if write_check && write_check =~ /^2/
      scanner.send_cmd(['RMD',dir], true)
      print_status("#{rhost}:#{rport} - User '#{user}' has READ/WRITE access")
      return 'Read/Write'
    else
      print_status("#{rhost}:#{rport} - User '#{user}' has READ access")
      return 'Read-only'
    end
  end
end
