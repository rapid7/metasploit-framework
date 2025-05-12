##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'readline'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Unix
  include Msf::Post::Linux::System
  include Msf::Post::Linux::Priv

  HELP_COMMANDS = [
    ['help', 'help', 0, 'Show current help'],
    ['?', 'help', 0, 'Show current help'],
    ['ls', 'dir', 1, 'List files and folders in a directory'],
    ['cat', 'read_file', 1, 'Show file contents'],
    ['whoami', 'whoami', 0, 'Show current user'],
    ['cd', 'cd', 1, 'Change current directory'],
    ['users', 'get_users', 0, 'Show list of users'],
    ['groups', 'get_groups', 0, 'Show list of groups'],
    ['pwd', 'pwd', 0, 'Show current PATH'],
    ['interfaces', 'interfaces', 0, 'Show list of network interfaces'],
    ['path', 'get_path', 0, 'Show current directories included in $PATH enviroment variable'],
    ['macs', 'macs', 0, 'Show list of MAC addresses'],
    ['shell', 'get_shell_name', 0, 'Show current SHELL'],
    ['hostname', 'get_hostname', 0, 'Show current Hostname'],
    ['ips', 'ips', 0, 'Show list of current IP addresses'],
    ['isroot?', 'is_root?', 0, 'Show if current user has root permissions'],
    ['exit', '', 0, 'Exit the Pseudo-shell'],
    ['tcp_ports', 'listen_tcp_ports', 0, 'Show list of listen TCP ports'],
    ['udp_ports', 'listen_udp_ports', 0, 'Show list of listen UDP ports'],
    ['clear', 'clear_screen', 0, 'Clear screen']
  ].sort

  LIST = [].sort
  HELP_COMMANDS.each do |linea|
    LIST.insert(-1, linea[0])
  end

  def initialize
    super(
      'Name' => 'Pseudo-Shell Post-Exploitation Module',
      'Description' => %q{
        This module will run a Pseudo-Shell.
      },
      'Author' => 'Alberto Rafael Rodriguez Iglesias <albertocysec[at]gmail.com>',
      'License' => MSF_LICENSE,
      'Platform' => ['linux'],
      'SessionTypes' => ['shell', 'meterpreter']
    )
  end

  def run
    @vhostname = get_hostname
    @vusername = whoami
    @vpromptchar = is_root? ? '#' : '$'
    prompt
  end

  def parse_cmd(cmd)
    parts = cmd.split(' ')
    return '' unless parts.length >= 1

    cmd = parts[0]
    nargs = parts.length - 1
    HELP_COMMANDS.each do |linea|
      next unless linea[0] == cmd

      func = linea[1]
      if nargs >= 1
        if linea[2] == 1
          args = parts[1]
        else
          nargs = 0
        end
      else
        args = ''
      end

      return func, cmd, args, nargs
    end

    error = get_shell_name
    message = "#{error}: #{cmd}: Command does not exist\n"
    print message
    message
  end

  def help
    print "\n"
    print "Commands Help\n"
    print "==============\n"
    print "\n"
    print format("\t%<cmd>-20s%<description>-100s\n", cmd: 'Command', description: 'Description')
    print format("\t%<cmd>-20s%<description>-100s\n", cmd: '-------', description: '-----------')
    HELP_COMMANDS.each do |linea|
      print format("\t%<cmd>-20s%<description>-100s\n", cmd: linea[0], description: linea[3])
    end
    print "\n"
  end

  def prompt_show
    promptshell = "#{@vusername}@#{@vhostname}:#{pwd.strip}#{@vpromptchar} "
    comp = proc { |s| LIST.grep(/^#{Regexp.escape(s)}/) }
    Readline.completion_append_character = ' '
    Readline.completion_proc = comp
    input = Readline.readline(promptshell, true)
    return nil if input.nil?

    input
  end

  def prompt
    while (input = prompt_show)
      break if input == 'exit'
      break if input == 'exit '

      begin
        func, command, args, nargs = parse_cmd(input)
        nargs = nargs.to_i
        if command == 'ls' && (nargs == 0)
          nargs += 1
          ruta = pwd
          args = ruta
        end
        if nargs > 0
          args = args.strip
          resultado = public_send(func.to_s, args.to_s)
        elsif input == ''
          resultado = []
          resultado.insert(-1, '')
        else
          resultado = public_send(func.to_s)
        end
        if !resultado.nil? == resultado
          if command == 'isroot?'
            print resultado ? "true\n" : "false\n"
          end
        elsif resultado.instance_of?(Array)
          print resultado.join("\n")
          print "\n"
        elsif resultado.strip != ''
          print resultado.chomp + "\n"
        end
      rescue StandardError # begin
        next
      end
    end
  end
end
