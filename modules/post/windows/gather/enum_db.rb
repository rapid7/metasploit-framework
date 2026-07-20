##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::Registry
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather Database Instance Enumeration',
        'Description' => %q{This module will enumerate a Windows system for installed database instances.},
        'License' => MSF_LICENSE,
        'Author' => [
          'Barry Shteiman <barry[at]sectorix.com>', # Module author
          'juan vazquez' # minor help
        ],
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        },
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_fs_search
              stdapi_sys_config_getenv
            ]
          }
        }
      )
    )
  end

  def run
    hostname = sysinfo.nil? ? cmd_exec('hostname') : sysinfo['Computer']
    print_status("Enumerating databases on #{hostname} (#{session.session_host})")

    results = []
    if check_mssql
      results += enumerate_mssql
    end
    if check_oracle
      results += enumerate_oracle
    end
    if check_db2
      results += enumerate_db2
    end
    if check_mysql
      results += enumerate_mysql
    end
    if check_sybase
      results += enumerate_sybase
    end

    if results.empty?
      print_status('Done, no databases were found')
      return
    end

    print_status("Done, #{results.length} databases found.")

    tbl = Rex::Text::Table.new(
      'Header' => 'Installed Databases',
      'Indent' => 1,
      'Columns' =>
        [
          'Type',
          'Instance',
          'Database',
          'Port'
        ]
    )

    results.each do |r|
      report_service(host: session.sock.peerhost, port: r[3], name: r[0], info: "#{r[0]}, #{r[1]}")
      tbl << r
    end

    print_line(tbl.to_s)
    p = store_loot('host.databases', 'text/plain', session, tbl.to_s, 'databases.txt', 'Running Databases')
    print_good("Results stored in: #{p}")
  end

  ##### initial identification methods #####

  # Check if MSSQL database instances are installed on host
  def check_mssql
    if registry_enumkeys('HKLM\\SOFTWARE\\Microsoft').include?('Microsoft SQL Server')
      print_status("\tMicrosoft SQL Server found.")
      return true
    end

    return false
  rescue StandardError
    return false
  end

  # Check if Oracle database instances are installed on host
  def check_oracle
    keys = registry_enumkeys('HKLM\\SOFTWARE\\Oracle')

    if keys.include?('ALL_HOMES')
      print_status("\tOracle Server found.")
      return true
    end

    if keys.include?('SYSMAN')
      print_status("\tOracle Server found.")
      return true
    end

    if keys.include?('KEY_XE')
      print_status("\tOracle Server found.")
      return true
    end

    return false
  rescue StandardError
    return false
  end

  # Check if DB2 database instances are installed on host
  def check_db2
    if registry_enumkeys('HKLM\\SOFTWARE\\IBM\\DB2').include?('GLOBAL_PROFILE')
      print_status("\tDB2 Server found.")
      return true
    end

    return false
  rescue StandardError
    return false
  end

  # Check if MySQL database instances are installed on host
  def check_mysql
    if registry_enumkeys('HKLM\\SOFTWARE').include?('MySQL AB')
      print_status("\tMySQL Server found.")
      return true
    end
    return false
  rescue StandardError
    return false
  end

  # Check if Sybase database instances are installed on host
  def check_sybase
    keys = registry_enumkeys('HKLM\\SOFTWARE\\Sybase')

    if keys.include?('SQLServer')
      print_status("\tSybase Server found.")
      return true
    end

    if keys.include?('Server')
      print_status("\tSybase Server found.")
      return true
    end

    return false
  rescue StandardError
    return false
  end

  ##### deep analysis methods #####

  # method to identify MSSQL instances
  def enumerate_mssql
    results = []
    key = 'HKLM\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\Instance Names\\SQL'
    instances = registry_enumvals(key)

    return results if instances.blank?

    instances.each do |i|
      tcpkey = "HKLM\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\#{registry_getvaldata(key, i)}\\MSSQLServer\\SuperSocketNetLib\\Tcp\\IPAll"
      tcpport = registry_getvaldata(tcpkey, 'TcpPort')
      print_good("\t\t+ #{registry_getvaldata(key, i)} (Port:#{tcpport})")
      results << ['mssql', "instance:#{registry_getvaldata(key, i)} port:#{tcpport}", 'Microsoft SQL Server', tcpport]
    end

    results
  rescue StandardError
    print_error("\t\t! could not identify information")
    return results || []
  end

  # method to identify oracle instances
  def enumerate_oracle
    results = []
    found_key = false
    basekey_set = ['HKLM\\SOFTWARE\\Oracle\\SYSMAN', 'HKLM\\SOFTWARE\\ORACLE\\KEY_XE']
    basekey_set.each do |basekey|
      next if found_key

      instances = registry_enumkeys(basekey)

      next if instances.blank?

      found_key = true

      instances.each do |i|
        if basekey.include? 'KEY_XE'
          oracle_sid = registry_getvaldata(basekey, 'ORACLE_SID')
          oracle_home = registry_getvaldata(basekey, 'ORACLE_HOME')
        else
          key = "#{basekey}\\#{i}"
          oracle_sid = registry_getvaldata(key, 'ORACLE_SID')
          oracle_home = registry_getvaldata(key, 'ORACLE_HOME')
        end

        if !exist?(oracle_home + '\\NETWORK\\ADMIN\\tnsnames.ora')
          print_error("\t\t! #{oracle_sid} (No Listener Found)")
          next
        end

        data_tnsnames = read_file(oracle_home + '\\NETWORK\\ADMIN\\tnsnames.ora')
        if data_tnsnames =~ /PORT\ =\ (\d+)/
          port = ::Regexp.last_match(1)
          print_good("\t\t+ #{oracle_sid} (Port:#{port})")
          results << [ 'oracle', "instance:#{oracle_sid} port:#{port}", 'Oracle Database Server', port ]
        else
          print_error("\t\t! #{oracle_sid} (No Listener Found)")
        end
      end
    end

    if !found_key
      print_error("\t\t! Oracle instances not found")
    end

    results
  rescue StandardError
    print_error("\t\t! could not identify information")
    return results || []
  end

  # method to identify mysql instances
  def enumerate_mysql
    results = []
    basekey = 'HKLM\\SOFTWARE\\MySQL AB'
    instances = registry_enumkeys(basekey)

    return results if instances.blank?

    instances.each do |i|
      key = "#{basekey}\\#{i}"
      location = registry_getvaldata(key, 'Location')

      data = read_mysql_conf(location)
      if data.nil?
        data = find_and_read_mysql_conf
      end

      if data && data =~ (/port=(\d+)/)
        port = ::Regexp.last_match(1)
        print_good("\t\t+ MYSQL (Port:#{port})")
        results << ['mysql', "instance:MYSQL port:#{port}", 'MySQL Server', port]
      else
        print_error("\t\t! could not identify information")
      end
    end

    results
  rescue StandardError
    print_error("\t\t! could not identify information")
    return results || []
  end

  # method to identify sybase instances
  def enumerate_sybase
    basekey = 'HKLM\\SOFTWARE\\Sybase\\SQLServer'
    instance = registry_getvaldata(basekey, 'DSLISTEN')
    location = registry_getvaldata(basekey, 'RootDir')
    results = []

    if !exist?(location + '\\ini\\sql.ini')
      print_error("\t\t! could not locate configuration file.")
      return results
    end

    data = read_file(location + '\\ini\\sql.ini')
    if data =~ /\[#{instance}\]([^\[]*)/
      segment = ::Regexp.last_match(1)
    else
      print_error("\t\t! could not locate information.")
      return results
    end

    if segment =~ /master=\w+,[^,]+,(\d+)/
      port = ::Regexp.last_match(1)
    else
      print_error("\t\t! could not locate information.")
      return results
    end

    print_good("\t\t+ #{instance} (Port:#{port})")
    results << [ 'sybase', "instance:#{instance} port:#{port}", 'Sybase SQL Server', port ]
    return results
  rescue StandardError
    print_error("\t\t! could not locate information.")
    return results || []
  end

  # method to identify db2 instances
  def enumerate_db2
    results = []
    cmd_i = cmd_exec('db2cmd', '-i -w /c db2ilist')
    cmd_p = cmd_exec('db2cmd', '-i -w /c db2 get dbm cfg')
    if cmd_p =~ %r{\ ?TCP/IP\ Service\ name\ +\(SVCENAME\)\ =\ (\w+)}
      port = ::Regexp.last_match(1)
    else
      print_error("\t\t! could not identify instances information")
      return results
    end

    windir = session.sys.config.getenv('windir')
    getfile = session.fs.file.search(windir + '\\system32\\drivers\\etc\\', 'services.*', true, -1)

    data = nil
    getfile.each do |file|
      if exist?("#{file['path']}\\#{file['name']}")
        data = read_file("#{file['path']}\\#{file['name']}")
        break if !data.nil?
      end
    end

    if data && data =~ (/#{port}[\ \t]+(\d+)/)
      port_t = ::Regexp.last_match(1)
    else
      print_error("\t\t! could not identify instances information")
      return results
    end

    cmd_i.split("\n").compact.each do |line|
      stripped = line.strip
      print_good("\t\t+ #{stripped} (Port:#{port_t})")
      results << [ 'db2', "instance:#{stripped} port:#{port_t}", 'DB2 Server', port_t ]
    end

    results
  rescue StandardError
    print_error("\t\t! could not identify instances information")
    return results || []
  end

  ##### helper methods #####

  def read_mysql_conf(location)
    return unless location

    if exist?(location + '\\my.ini')
      return read_file(location + '\\my.ini')
    end

    if exist?(location + '\\my.cnf')
      return read_file(location + '\\my.cnf')
    end

    nil
  end

  def find_and_read_mysql_conf
    sysdriv = session.sys.config.getenv('SYSTEMDRIVE')
    getfile = session.fs.file.search(sysdriv + '\\', 'my.ini', true, -1)
    getfile.each do |file|
      path = "#{file['path']}\\#{file['name']}"
      if exist?(path)
        return read_file(path)
      end
    end

    nil
  end
end
