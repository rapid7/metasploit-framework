##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  include Msf::Post::File
  include Msf::Post::Linux::Priv
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Sudo Commands',
      'Description'   => %q{
        This module examines the sudoers configuration for the session user
        and lists the commands executable via sudo.

        This module also inspects each command and reports potential avenues
        for privileged code execution due to poor file system permissions or
        permitting execution of executables known to be useful for privesc,
        such as utilities designed for file read/write, user modification,
        or execution of arbitrary operating system commands.

        Note, you may need to provide the password for the session user.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'bcoles' ],
      'Platform'      => [ 'bsd', 'linux', 'osx', 'solaris', 'unix' ],
      'SessionTypes'  => [ 'meterpreter', 'shell' ]
    ))
    register_options [
      OptString.new('SUDO_PATH', [ true, 'Path to sudo executable', '/usr/bin/sudo' ]),
      OptString.new('PASSWORD', [ false, 'Password for the current user', '' ])
    ]
  end

  def sudo_path
    datastore['SUDO_PATH'].to_s
  end

  def password
    datastore['PASSWORD'].to_s
  end

  def is_executable?(path)
    cmd_exec("test -x '#{path}' && echo true").include? 'true'
  end

  def eop_bins
    %w[
      cat chgrp chmod chown cp echo find less ln mkdir more mv tail tar
      usermod useradd userdel
      env crontab
      awk gdb gawk lua irb ld node perl php python python2 python3 ruby tclsh wish
      ncat netcat netcat.traditional nc nc.traditional openssl socat telnet telnetd
      ash bash csh dash ksh sh zsh
      su sudo
      expect ionice nice script setarch strace taskset time
      wget curl ftp scp sftp ssh tftp
      nmap
      ed emacs man nano vi vim visudo
      dpkg rpm rpmquery
    ]
  end

  #
  # Check if a sudo command offers prvileged code execution
  #
  def check_eop(cmd)
    # drop args for simplicity (at the risk of false positives)
    cmd = cmd.split(/\s/).first

    if cmd.eql? 'ALL'
      print_good 'sudo any command!'
      return true
    end

    base_dir  = File.dirname cmd
    base_name = File.basename cmd

    if file_exist? cmd
      if writable? cmd
        print_good "#{cmd} is writable!"
        return true
      end
    elsif writable? base_dir
      print_good "#{cmd} does not exist and #{base_dir} is writable!"
      return true
    end

    if eop_bins.include? base_name
      print_good "#{cmd} matches known privesc executable '#{base_name}' !"
      return true
    end

    false
  end

  #
  # Retrieve list of sudo commands for current session user
  #
  def sudo_list
    # try non-interactive (-n) without providing a password
    cmd = "#{sudo_path} -n -l"
    vprint_status "Executing: #{cmd}"
    output = cmd_exec(cmd).to_s

    if output.start_with?('usage:') || output.include?('illegal option') || output.include?('a password is required')
      # try with a password from stdin (-S)
      cmd = "echo #{password} | #{sudo_path} -S -l"
      vprint_status "Executing: #{cmd}"
      output = cmd_exec(cmd).to_s
    end

    output
  end

  #
  # Format sudo output and extract permitted commands
  #
  def parse_sudo(sudo_data)
    cmd_data = sudo_data.scan(/may run the following commands.*?$(.*)\z/m).flatten.first

    # remove leading whitespace from each line and remove linewraps
    formatted_data = ''
    cmd_data.split("\n").reject { |line| line.eql?('') }.each do |line|
      formatted_line = line.gsub(/^\s*/, '').to_s
      if formatted_line.start_with? '('
        formatted_data << "\n#{formatted_line}"
      else
        formatted_data << " #{formatted_line}"
      end
    end

    formatted_data.split("\n").reject { |line| line.eql?('') }.each do |line|
      run_as = line.scan(/^\((.+?)\)/).flatten.first

      if run_as.blank?
        print_warning "Could not parse sudoers entry: #{line.inspect}"
        next
      end

      user = run_as.split(':')[0].to_s.strip || ''
      group = run_as.split(':')[1].to_s.strip || ''
      no_passwd = false

      cmds = line.scan(/^\(.+?\) (.+)$/).flatten.first
      if cmds.start_with? 'NOPASSWD:'
        no_passwd = true
        cmds = cmds.gsub(/^NOPASSWD:\s*/, '')
      end

      # Commands are separated by commas but may also contain commas (escaped with a backslash)
      # so we temporarily replace escaped commas with some junk
      # later, we'll replace each instance of the junk with a comma
      junk = Rex::Text.rand_text_alpha(10)
      cmds = cmds.gsub('\, ', junk)

      cmds.split(', ').each do |cmd|
        cmd = cmd.gsub(junk, ', ').strip

        if cmd.start_with? '('
          run_as = cmd.scan(/^\((.+?)\)/).flatten.first

          if run_as.blank?
            print_warning "Could not parse sudo command: #{cmd.inspect}"
            next
          end

          user = run_as.split(':')[0].to_s.strip || ''
          group = run_as.split(':')[1].to_s.strip || ''
          cmd = cmd.scan(/^\(.+?\) (.+)$/).flatten.first
        end

        msg = "Command: #{cmd.inspect}"
        msg << " RunAsUsers: #{user}" unless user.eql? ''
        msg << " RunAsGroups: #{group}" unless group.eql? ''
        msg << ' without providing a password' if no_passwd
        vprint_status msg

        eop = check_eop cmd

        @results << [cmd, user, group, no_passwd ? '' : 'True', eop ? 'True' : '']
      end
    end
  rescue => e
    print_error "Could not parse sudo ouput: #{e.message}"
  end

  def run
    if is_root?
      fail_with Failure::BadConfig, 'Session already has root privileges'
    end

    unless is_executable? sudo_path
      print_error 'Could not find sudo executable'
      return
    end

    output = sudo_list
    vprint_line output
    vprint_line

    if output.include? 'Sorry, try again'
      fail_with Failure::NoAccess, 'Incorrect password'
    end

    if output =~ /^Sorry, .* may not run sudo/
      fail_with Failure::NoAccess, 'Session user is not permitted to execute any commands with sudo'
    end

    if output !~ /may run the following commands/
      fail_with Failure::NoAccess, 'Incorrect password, or the session user is not permitted to execute any commands with sudo'
    end

    @results = Rex::Text::Table.new(
      'Header'  => 'Sudo Commands',
      'Indent'  => 2,
      'Columns' =>
        [
          'Command',
          'RunAsUsers',
          'RunAsGroups',
          'Password?',
          'Privesc?'
        ]
    )

    parse_sudo output

    if @results.rows.empty?
      print_status 'Found no sudo commands for the session user'
      return
    end

    print_line
    print_line @results.to_s

    path = store_loot(
      'sudo.commands',
      'text/csv',
      session,
      @results.to_csv,
      'sudo.commands.txt',
      'Sudo Commands'
    )

    print_good "Output stored in: #{path}"
  end
end
