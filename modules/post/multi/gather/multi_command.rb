##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Multi Gather Run Shell Command Resource File',
        'Description' => %q{
          This module will read shell commands from a resource file and
          execute the commands in the specified Meterpreter or shell session.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
        'Platform' => %w[bsd linux osx unix win],
        'SessionTypes' => ['meterpreter'],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )
    register_options(
      [
        OptString.new('RESOURCE', [true, 'Full path to resource file to read commands from.', nil])
      ]
    )
  end

  def run
    raise 'Resource File does not exist!' unless ::File.exist?(datastore['RESOURCE'])

    hostname = sysinfo.nil? ? cmd_exec('hostname') : sysinfo['Computer']
    print_status("Running module against #{hostname} (#{session.session_host})")

    ::File.open(datastore['RESOURCE'], 'rb').each_line do |cmd|
      next if cmd.strip.empty?
      next if cmd.start_with?('#')

      begin
        tmpout = "\n"
        tmpout << "*****************************************\n"
        tmpout << "      Output of #{cmd}\n"
        tmpout << "*****************************************\n"
        print_status "Running command #{cmd.chomp}"
        tmpout << cmd_exec(cmd.chomp)
        vprint_status(tmpout)
        command_log = store_loot(
          'host.command',
          'text/plain',
          session,
          tmpout,
          "#{cmd.gsub(%r{\.|/|\s}, '_')}.txt",
          "Command Output '#{cmd.chomp}'"
        )
        print_good("Command output saved to: #{command_log}")
      rescue StandardError => e
        print_bad("Error Running Command #{cmd.chomp}: #{e.class} #{e}")
      end
    end
  end
end
