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
    datastore['PASSWORD'] ? datastore['PASSWORD'].to_s : session.exploit_datastore['PASSWORD']
  end

  def is_writable?(path)
    cmd_exec("test -w '#{path}' && echo true").include? 'true'
  end

  def is_executable?(path)
    cmd_exec("test -x '#{path}' && echo true").include? 'true'
  end

  def eop_bins
    %w[
      cat chgrp chmod chown cp echo find less ln mkdir more mv tail tar
      usermod useradd userdel
      crontab
      awk gawk perl python ruby irb lua
      netcat netcat.traditional nc nc.traditional openssl telnetd
      sh ash bash ksh zsh
      su sudo
      wget curl
      nmap
      man emacs nano vi vim visudo
    ]
  end

  def check_eop(cmd)
    # drop args for simplicity at the risk of false positives
    cmd = cmd.split(/\s/).first

    if cmd.eql? 'ALL'
      print_good 'sudo any command!'
      return true
    end

    base_dir  = File.dirname cmd
    base_name = File.basename cmd

    if file_exist? cmd
      if is_writable? cmd
        print_good "#{cmd} is writable!"
        return true
      end
    elsif is_writable? base_dir
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
    cmd = "#{sudo_path} -l -l -n"
    vprint_status "Executing: #{cmd}"
    output = cmd_exec(cmd).to_s

    if output.start_with?('usage:') || output.include?('a password is required')
      # try with a password from stdin (-S)
      cmd = "echo #{password} | #{sudo_path} -S -l -l"
      vprint_status "Executing: #{cmd}"
      output = cmd_exec(cmd).to_s
    end

    output
  end

  def parse_sudo(entry)
    entry.split(/^\s*RunAsUsers: /).flatten.each { |s| parse_segment(s) }
  rescue => e
    print_error "Could not parse sudoers entry: #{e.message}"
  end

  def parse_segment(segment)
    users = segment.split("\n").first.strip

    if users.eql? ''
      print_warning 'Could not parse sudoers entry'
      return
    end

    groups = segment.scan(/^\s*RunAsGroups: (.*)$/).flatten.first || ''
    options = segment.scan(/^\s*Options: (.*)$/).flatten.first || ''

    commands = []
    # Assuming the entirety of the remainder of the segment
    # following the 'Commands:' directive contains only commands.
    # This appears to be a safe assumption in testing.
    segment.scan(/^\s*Commands:\s*(.*)\z/m).flatten.each do |cmd_data|
      # Long commands may linewrap on older versions of sudo.
      # Preventing the linewrap requires a proper TTY,
      # so we rely on the whitespace indentation instead:
      # - 8 spaces for start of a new command
      # - 4 spaces for continuation of a linewrapped command
      # first we'll remove all indentation for lines with 8 spaces of indentation
      cmd_data = cmd_data.gsub(/^\s{8}/, '')
      # now we'll remove the wrap by replacing all newlines followed by 4 spaces of indentation with a space
      cmd_data = cmd_data.gsub(/\n\s{4}/, ' ')
      # now we'll split by line, hoping the linewraps have been fixed
      cmd_data.split(/\n/).each do |cmd|
        # Commands are separated by commas but may also contain commas (escaped with a backslash)
        # so we temporarily replace escaped commas with some junk
        # later, we'll replace each instance of the junk with a comma
        junk = Rex::Text.rand_text_alpha(10)
        cmd = cmd.gsub('\,', junk)
        cmd.split(',').each do |csv|
          commands << csv.gsub(junk, ',').strip
        end
      end
    end

    commands.each do |cmd|
      no_passwd = false

      if cmd.start_with? 'NOPASSWD:'
        no_passwd = true
        cmd = cmd.gsub(/^NOPASSWD:\s*/, '')
      end

      if options.include? '!authenticate'
        no_passwd = true
      end

      msg = "Command: #{cmd.inspect}"
      msg << " RunAsUsers: #{users}" unless users.eql? ''
      msg << " RunAsGroups: #{groups}" unless groups.eql? ''
      msg << ' without providing a password' if no_passwd
      vprint_status msg

      eop = check_eop cmd

      @results << [cmd, users, groups, !no_passwd, eop]
    end
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
    vprint_status 'Output:'
    vprint_line output
    vprint_line

    if output.include? 'Sorry, try again'
      fail_with Failure::NoAccess, 'Incorrect password'
    end

    if output.eql? ''
      fail_with Failure::NoAccess, 'Incorrect password, or the session user is not permitted to execute any commands with sudo'
    end

    entries = output.split("\n\n").select { |e| e.start_with? 'Sudoers entry' }

    if entries.empty?
      fail_with Failure::NoAccess, 'Found no sudo entries for the session user'
    end

    print_good "Found #{entries.length} sudo entries for current user"

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

    entries.each { |entry| parse_sudo entry }

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
