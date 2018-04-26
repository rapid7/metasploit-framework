##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Linux Gather Container Detection',
        'Description'   => %q{
          This module attempts to determine whether the system is running
          inside of a container and if so, which one. This module supports
          detection of Docker, LXC, and systemd nspawn.},
        'License'       => MSF_LICENSE,
        'Author'        => [ 'James Otten <jamesotten1[at]gmail.com>'],
        'Platform'      => [ 'linux' ],
        'SessionTypes'  => [ 'shell', 'meterpreter' ]
      ))
  end

  # Run Method for when run command is issued
  def run
    container = nil

    # Check for .dockerenv file
    if container.nil?
      if file?("/.dockerenv")
        container = "Docker"
      end
    end

    # Check cgroup on PID 1
    if container.nil?
      cgroup = read_file("/proc/1/cgroup")
      if cgroup
        case cgroup.tr("\n", " ")
        when /docker/i
          container = "Docker"
        when /lxc/i
          container = "LXC"
        end
      end
    end

    # Check for the "container" environment variable
    if container.nil?
      container_variable = get_env("container")
      case container_variable
      when "lxc"
        container = "LXC"
      when "systemd-nspawn"
        container = "systemd nspawn"
      end
    end

    if container
      print_good("This appears to be a '#{container}' container")
      report_virtualization(container)
    else
      print_status("This does not appear to be a container")
    end
  end
end
