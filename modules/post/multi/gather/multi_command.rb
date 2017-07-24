##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Multi Gather Run Shell Command Resource File',
        'Description'   => %q{ This module will read shell commands from a resource file and
          execute the commands in the specified Meterpreter or shell session.},
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
        'Platform'      => %w{ bsd linux osx unix win },
        'SessionTypes'  => ['meterpreter']
      ))
    register_options(
      [
        OptString.new('RESOURCE', [true, 'Full path to resource file to read commands from.', nil])

      ])
  end

  # Run Method for when run command is issued
  def run
    print_status("Running module against #{sysinfo['Computer']}")
    if not ::File.exist?(datastore['RESOURCE'])
      raise "Resource File does not exists!"
    else
      ::File.open(datastore['RESOURCE'], "rb").each_line do |cmd|
        next if cmd.strip.length < 1
        next if cmd[0,1] == "#"
        begin
          tmpout = "\n"
          tmpout << "*****************************************\n"
          tmpout << "      Output of #{cmd}\n"
          tmpout << "*****************************************\n"
          print_status "Running command #{cmd.chomp}"
          tmpout << cmd_exec(cmd.chomp)
          vprint_status tmpout
          command_log = store_loot("host.command", "text/plain", session,tmpout ,
            "#{cmd.gsub(/\.|\/|\s/,"_")}.txt", "Command Output \'#{cmd.chomp}\'")
          print_good("Command output saved to: #{command_log}")
        rescue ::Exception => e
          print_bad("Error Running Command #{cmd.chomp}: #{e.class} #{e}")
        end
      end
    end
  end
end
