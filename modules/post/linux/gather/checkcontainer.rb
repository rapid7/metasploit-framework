##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Linux::System

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Linux Gather Container Detection',
        'Description' => %q{
          This module attempts to determine whether the system is running
          inside of a container and if so, which one. This module supports
          detection of Docker, WSL, LXC, Podman and systemd nspawn.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'James Otten <jamesotten1[at]gmail.com>'],
        'Platform' => %w[linux unix],
        'SessionTypes' => %w[shell meterpreter],
        'Notes' => {
          'Stability' => [ CRASH_SAFE ],
          'Reliability' => [ REPEATABLE_SESSION ],
          'SideEffects' => []
        }
      )
    )
  end

  # Run Method for when run command is issued
  def run
    container = get_container_type

    if container == 'Unknown'
      print_status('This does not appear to be a container')
    else
      print_good("This appears to be a '#{container}' container")
    end
  end
end
