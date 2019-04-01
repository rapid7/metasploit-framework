##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/mqtt'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::MQTT
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute

  def initialize
    super(
      'Name'        => 'MQTT Authentication Scanner',
      'Description' => %q(
        This module attempts to authenticate to MQTT.
      ),
      'Author'      =>
        [
          'Jon Hart <jon_hart[at]rapid7.com>'
        ],
      'References'     =>
        [
          ['URL', 'http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Table_3.1_-']
        ],
      'License'     => MSF_LICENSE,
      'DefaultOptions' =>
        {
          'BLANK_PASSWORDS' => false,
          'USER_AS_PASS' => true,
          'USER_FILE' => 'data/wordlists/unix_users.txt',
          'PASS_FILE' => 'data/wordlists/unix_passwords.txt'
        }
    )
  end

  def test_login(username, password)
    client_opts = {
      username: username,
      password: password,
      read_timeout: read_timeout,
      client_id: client_id
    }
    connect
    client = Rex::Proto::MQTT::Client.new(sock, client_opts)
    connect_res = client.connect
    client.disconnect
    connect_res.return_code.zero?
  end

  def default_login
    vprint_status("Testing without credentials")
    if test_login('', '')
      print_good("Does not require authentication")
    end

  end

  def run_host(_ip)
    unless default_login
      brute
    end
  end

  def brute
    vprint_status("Starting MQTT login sweep")

    cred_collection = Metasploit::Framework::CredentialCollection.new(
      blank_passwords: datastore['BLANK_PASSWORDS'],
      pass_file: datastore['PASS_FILE'],
      password: datastore['PASSWORD'],
      user_file: datastore['USER_FILE'],
      userpass_file: datastore['USERPASS_FILE'],
      username: datastore['USERNAME'],
      user_as_pass: datastore['USER_AS_PASS']
    )

    cred_collection = prepend_db_passwords(cred_collection)

    scanner = Metasploit::Framework::LoginScanner::MQTT.new(
      host: rhost,
      port: rport,
      read_timeout: datastore['READ_TIMEOUT'],
      client_id: client_id,
      proxies: datastore['PROXIES'],
      cred_details: cred_collection,
      stop_on_success: datastore['STOP_ON_SUCCESS'],
      bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
      connection_timeout: datastore['ConnectTimeout'],
      max_send_size: datastore['TCP::max_send_size'],
      send_delay: datastore['TCP::send_delay'],
      framework: framework,
      framework_module: self,
      ssl: datastore['SSL'],
      ssl_version: datastore['SSLVersion'],
      ssl_verify_mode: datastore['SSLVerifyMode'],
      ssl_cipher: datastore['SSLCipher'],
      local_port: datastore['CPORT'],
      local_host: datastore['CHOST']
    )

    scanner.scan! do |result|
      credential_data = result.to_h
      credential_data.merge!(
        module_fullname: fullname,
        workspace_id: myworkspace_id
      )
      password = result.credential.private
      username = result.credential.public
      if result.success?
        credential_core = create_credential(credential_data)
        credential_data[:core] = credential_core
        create_credential_login(credential_data)
        print_good("MQTT Login Successful: #{username}/#{password}")
      else
        invalidate_login(credential_data)
        vprint_error("MQTT LOGIN FAILED: #{username}/#{password} (#{result.proof})")
      end
    end
  end
end
