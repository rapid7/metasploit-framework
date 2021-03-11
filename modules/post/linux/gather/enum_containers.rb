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
          This module attempts to enumerate containers on the target machine and optionally run a command on each active container found.
          Currently it supports Docker, LXC and RKT.
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
      command = 'docker >/dev/null 2>&1 && echo true'
    when 'lxc'
      command = 'lxc >/dev/null 2>&1 && echo true'
    when 'rkt'
      # Apparently rkt doesn't play nice with 2>&1 for most commands, though `rkt help`
      # seems to be fine so this is why its used here vs just 'rkt'
      command = 'rkt help >/dev/null 2>&1 && echo true'
    else
      print_error("Invalid container type #{container_type}")
      return false
    end
    cmd_exec(command) =~ /true$/
  end

  # Count the number of currently running containers
  def count_containers(container_type, count_inactive: true)
    case container_type
    when 'docker'
      command = if count_inactive
                  'docker container ls --format "{{.Names}}" | wc -l'
                else
                  'docker container ls -a --format "{{.Names}}" | wc -l'
                end
    when 'lxc'
      command = if count_inactive
                  'lxc list -c n --format csv | wc -l'
                else
                  'lxc list -c n,s --format csv | grep ,RUNNING | wc -l'
                end
    when 'rkt'
      command = if count_inactive
                  'rkt list | tail -n +2 | wc -l'
                else
                  'rkt list | tail -n +2 | grep running | wc -l'
                end
    else
      print_error("Invalid container type '#{container_type}'")
      return 0
    end

    result = cmd_exec(command)
    if result =~ /denied/
      print_error("Was unable to enumerate the number of #{container_type} containers due to a lack of permissions!")
      return 0
    else
      result.to_i
    end
  end

  # List containers
  def list_containers(container_type)
    case container_type
    when 'docker'
      result = cmd_exec('docker container ls -a')
    when 'lxc'
      # LXC does some awful table formatting, lets try and fix it to be more uniform
      result = cmd_exec('lxc list').each_line.reject { |st| st =~ /^\+--/ }.map.with_index.map do |s, i|
        if i == 0
          s.split('| ').map { |t| t.strip.ljust(t.size, ' ').gsub(/\|/, '') }.join + "\n"
        else
          s.gsub(/\| /, '').gsub(/\|/, '')
        end
      end.join.strip
    when 'rkt'
      result = cmd_exec('rkt list')
    else
      print_error("Invalid container type '#{container_type}'")
      return nil
    end
    result
  end

  # List running containers identifiers
  def list_running_containers_id(container_type)
    case container_type
    when 'docker'
      command = 'docker container ls --format "{{.Names}}"'
    when 'lxc'
      command = 'lxc list -c n,s --format csv 2>/dev/null | grep ,RUNNING|cut -d, -f1'
    when 'rkt'
      command = 'rkt list | tail -n +2 | cut -f1'
    else
      print_error("Invalid container type '#{container_type}'")
      return nil
    end
    cmd_exec(command).each_line.map(&:strip)
  end

  # Execute a command on a container
  def container_execute(container_type, container_identifier, command)
    case container_type
    when 'docker'
      command = "docker exec '#{container_identifier}' #{command}"
    when 'lxc'
      command = "lxc exec '#{container_identifier}' -- #{command}"
    when 'rkt'
      print_error("RKT containers do not support command execution\nUse the command \"rkt enter '#{container_identifier}'\" to manually enumerate this container")
      return nil
    else
      print_error("Invalid container type '#{container_type}'")
      return nil
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
      print_good("#{platform} was found on the system!")
      num_containers = count_containers(platform, count_inactive: false)

      if num_containers == 0
        print_error("No active or inactive containers were found for #{platform}\n")
      else
        num_running_containers = count_containers(platform, count_inactive: true)
        print_good("#{platform}: #{num_running_containers} Running Containers / #{num_containers} Total")
      end

      next unless num_containers > 0

      containers = list_containers(platform)
      next if containers.nil?

      # Using print so not to mess up table formatting
      print_line(containers.to_s)

      p = store_loot("host.#{platform}_containers", 'text/plain', session, containers, "#{platform}_containers.txt", "#{platform} Containers")
      print_good("Results stored in: #{p}\n")

      next if cmd.blank?

      running_container_ids = list_running_containers_id(platform)
      next if running_container_ids.nil?

      running_container_ids.each do |container_id|
        print_status("Executing command on #{platform} container #{container_id}")
        command_result = container_execute(platform, container_id, cmd)
        next if command_result.nil?

        print_good(command_result)
        p = store_loot("host.#{platform}_command_results", 'text/plain', session, command_result, "#{platform}_containers_command_results.txt", "#{platform} Containers Command Results")
        print_good("Command execution results stored in: #{p}\n")
      end
    end
  end
end
