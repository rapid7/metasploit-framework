##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::WMIC

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather Run WMIC Commands',
        'Description' => %q{
          This module executes WMIC commands on the specified host.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )

    register_options([
      OptPath.new('RESOURCE', [false, 'Full path to resource file containing WMIC commands']),
      OptString.new('COMMAND', [false, 'WMIC command']),
    ])
  end

  def run
    hostname = sysinfo.nil? ? cmd_exec('hostname') : sysinfo['Computer']
    print_status("Running module against #{hostname} (#{session.session_host})")

    resource_file = datastore['RESOURCE']
    command = datastore['COMMAND']

    if command.blank? && resource_file.blank?
      fail_with(Failure::BadConfig, 'Please specify COMMAND or RESOURCE file.')
    end

    commands = []

    if resource_file
      fail_with(Failure::BadConfig, "Resource file #{resource_file} does not exist!") unless ::File.exist?(resource_file)

      ::File.open(resource_file).each_line(chomp: true) do |cmd|
        next if cmd.strip.empty?
        next if cmd.starts_with?('#')

        commands << cmd
      end
    else
      commands << command
    end

    commands.each do |cmd|
      next if cmd.strip.empty?

      print_status("Running WMIC command: #{cmd}")

      result = wmic_query(cmd)

      if result.blank?
        print_error('No results for command')
        next
      end

      vprint_line(result)

      store_wmic_loot(result, cmd)
    end
  end

  def store_wmic_loot(result_text, cmd)
    command_log = store_loot(
      'host.command.wmic',
      'text/plain',
      session,
      result_text,
      "#{cmd.gsub(%r{\.|/|\s}, '_')}.txt",
      "Command Output 'wmic #{cmd}'"
    )

    print_status("Command output saved to: #{command_log}")
  end
end
