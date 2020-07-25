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
        'Name' => 'Linux Container Enumeration',
        'Description' => %q{
          This module attempts to enumeratec containers on the target machine and optionally run a command on each active container found..
          Supports Docker, LXC and RKT.
        },
        'License' => MSF_LICENSE,
        'Author' => ['stealthcopter'],
        'Platform' => ['linux'],
        'SessionTypes' => ['shell', 'meterpreter']
      )
    )
    register_options(
      [
        OptString.new('CMD', [false, 'Optional command to run on each running container', ''])
      ]
    )
  end

  def cmd
    datastore['CMD']
  end

  # Check if a container program is installed and usable by current user
  def runnable(container_type)
    case container_type
    when 'docker'
      command = 'docker container ls -a >/dev/null 2>&1 && echo true'
    when 'lxc'
      command = 'lxc list >/dev/null 2>&1 && echo true'
    when 'rkt'
      command = 'rkt list >/dev/null 2>&1 && echo true'
    else
      print_error("Invalid container type #{container_type}")
      return false
    end
    cmd_exec(command) =~ /true$/
  end

  # Count the number of currently running containers
  def count_containers(container_type, count_inactive = true)
    case container_type
    when 'docker'
      command = if count_inactive
                  'docker container ls --format "{{.Names}}" 2>/dev/null | wc -l'
                else
                  'docker container ls -a --format "{{.Names}}" 2>/dev/null | wc -l'
                end
    when 'lxc'
      command = if count_inactive
                  'lxc list -c n --format csv 2>/dev/null | wc -l'
                else
                  'lxc list -c n,s --format csv 2>/dev/null | grep ,RUNNING | wc -l'
                end
    when 'rkt'
      command = if count_inactive
                  'rkt list 2>/dev/null | tail -n +2 | wc -l'
                else
                  'rkt list 2>/dev/null | grep running | tail -n +2 | wc -l'
                end
    else
      print_error("Invalid container type '#{container_type}'")
      return 0
    end
    cmd_exec(command).to_i
  end

  # List containers
  def list_containers(container_type)
    case container_type
    when 'docker'
      command = 'docker container ls -a'
    when 'lxc'
      command = 'lxc list'
    when 'rkt'
      command = 'rkt list'
    else
      print_error("Invalid container type '#{container_type}'")
      return false
    end
    cmd_exec(command)
  end

  # List running containers identifiers
  def list_running_containers_id(container_type)
    case container_type
    when 'docker'
      command = 'docker container ls --format "{{.Names}}"'
    when 'lxc'
      command = 'lxc list -c n,s --format csv 2>/dev/null | grep ,RUNNING|cut -d, -f1'
    when 'rkt'
      command = 'rkt list| tail -n +2| cut -f1'
    else
      print_error("Invalid container type '#{container_type}'")
      return false
    end
    cmd_exec(command).each_line.map(&:strip)
  end

  # Execute a command on a container
  def container_execute(container_type, container_identifier, command = 'env')
    case container_type
    when 'docker'
      command = "docker exec '#{container_identifier}' #{command}"
    when 'lxc'
      command = "lxc exec '#{container_identifier}' -- #{command}"
    when 'rkt'
      print_error("RKT containers do not support command execution\nUse rkt enter '#{container_identifier}' to manually enumerate this container")
    else
      print_error("Invalid container type '#{container_type}'")
      return false
    end
    vprint_status("Running #{command}")
    cmd_exec(command)
  end

  # Run Method for when run command is issued
  def run
    platforms = %w[docker lxc rkt].select { |p| runnable(p) }

    if platforms.empty?
      print_error('No container software appears to be installed or runnable by the current user')
      return
    end

    platforms.each do |platform|
      num_containers = count_containers(platform)
      num_running_containers = count_containers(platform, false)

      if num_containers == 0
        print_good("#{platform} found but no active or inactive containers were found")
      else
        print_good("#{platform}: #{num_running_containers} Running Containers / #{num_containers} Total")
      end

      next unless num_containers

      containers = list_containers(platform)
      print_good("\n#{containers}\n")

      next if cmd.blank?

      running_container_ids = list_running_containers_id(platform)
      running_container_ids.each do |container_id|
        print_status("Executing command on #{platform} container #{container_id}")
        print_good(container_execute(platform, container_id, cmd))
      end
    end
  end
end
