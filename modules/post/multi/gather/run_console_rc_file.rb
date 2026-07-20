##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Multi Gather Run Console Resource File',
        'Description' => %q{
          This module will read console commands from a resource file and
          execute the commands in the specified Meterpreter session.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )
    register_options(
      [
        OptString.new('RESOURCE', [true, 'Full path to resource file to read commands from.', nil]),
      ]
    )
  end

  def run
    if !::File.exist?(datastore['RESOURCE'])
      raise 'Resource File does not exist!'
    end

    hostname = sysinfo.nil? ? cmd_exec('hostname') : sysinfo['Computer']
    print_status("Running module against #{hostname} (#{session.session_host})")

    ::File.open(datastore['RESOURCE'], 'rb').each_line do |cmd|
      next if cmd.strip.empty?
      next if cmd.start_with?('#')

      begin
        print_status "Running command #{cmd.chomp}"
        session.console.run_single(cmd.chomp)
      rescue StandardError => e
        print_status("Error Running Command #{cmd.chomp}: #{e.class} #{e}")
      end
    end
  end
end
