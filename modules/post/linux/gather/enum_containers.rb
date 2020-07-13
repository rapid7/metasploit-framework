##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Linux Container Enumeration',
      'Description' => %q{
        This module attempts to enumerate containers running on the target machine.
        Supports Docker, LXC and RKT.
      },
      'License' => MSF_LICENSE,
      'Author' => ['Mat Rollings'],
      'Platform' => ['linux'],
      'SessionTypes' => ['shell', 'meterpreter']
    ))
  end

  # Check if a container program is installed and usable by current user
  def runnable(container_type)
    case container_type
    when 'docker'
      result = cmd_exec('docker ps >/dev/null 2>&1 && echo true')
    when 'lxc'
      result = cmd_exec('lxc list >/dev/null 2>&1 && echo true')
    when 'rkt'
      result = cmd_exec('rkt list >/dev/null 2>&1 && echo true')
    else
      print_error("Invalid container type #{container_type}")
      return false
    end
    result =~ /true$/
  end

  # Count the number of currently running containers
  def count_containers(container_type)
    case container_type
    when 'docker'
      result = cmd_exec('docker ps --format "{{.Names}}" 2>/dev/null | wc -l')
    when 'lxc'
      result = cmd_exec('lxc list -c n --format csv 2>/dev/null | wc -l')
    when 'rkt'
      result = cmd_exec('rkt list 2>/dev/null | tail -n +2  | wc -l')
    else
      print_error("Invalid container type '#{container_type}'")
      return 0
    end
    result.to_i
  end

  # List the currently running containers
  def list_containers(container_type)
    case container_type
    when 'docker'
      result = cmd_exec('docker ps')
    when 'lxc'
      result = cmd_exec('lxc list')
    when 'rkt'
      result = cmd_exec('rkt list')
    else
      print_error("Invalid container type '#{container_type}'")
      return false
    end
    result
  end

  # Run Method for when run command is issued
  def run
    platforms = %w[docker lxc rkt]
    platforms_found = false

    platforms.each do |platform|
      if runnable(platform)
        platforms_found = true
        no_active = count_containers(platform)
        print_good("#{platform}: #{no_active} Active Containers")
        if noActive > 0
          containers = list_containers(platform)
          print("#{containers}\n")
        end
      else
        vprint_status("#{platform} is either not installed or not runnable by current user")
      end
    end

    unless platforms_found
      print_error('No container software appears to be installed')
    end
  end
end
