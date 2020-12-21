##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/report'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::Registry
  include Msf::Auxiliary::Report

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Gather Database Instance Enumeration',
      'Description'   => %q{ This module will enumerate a windows system for installed database instances },
      'License'       => MSF_LICENSE,
      'Author'        => [
        'Barry Shteiman <barry[at]sectorix.com>', # Module author
        'juan vazquez' # minor help
      ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
  end

  # method called when command run is issued
  def run

    results = []

    print_status("Enumerating Databases on #{sysinfo['Computer']}")
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
      print_status("Done, No Databases were found")
      return
    end

    print_status("Done, Databases Found.")

    tbl = Rex::Text::Table.new(
      'Header'  => "Installed Databases",
      'Indent'  => 1,
      'Columns' =>
        [
          "Type",
          "Instance",
          "Database",
          "Port"
        ])

    results.each { |r|
      report_service(:host => session.sock.peerhost, :port => r[3], :name => r[0], :info => "#{r[0]}, #{r[1]}")
      tbl << r
    }

    print_line(tbl.to_s)
    p = store_loot("host.databases", "text/plain", session, tbl.to_s, "databases.txt", "Running Databases")
    print_good("Results stored in: #{p}")

  end

  ##### initial identification methods #####

  # method for Checking if database instances are installed on host - mssql
  def check_mssql
    key = "HKLM\\SOFTWARE\\Microsoft"
    if registry_enumkeys(key).include?("Microsoft SQL Server")
      print_status("\tMicrosoft SQL Server found.")
      return true
    end
    return false
  rescue
    return false
  end

  # method for Checking if database instances are installed on host - oracle
  def check_oracle
    key = "HKLM\\SOFTWARE\\Oracle"
    if registry_enumkeys(key).include?("ALL_HOMES")
      print_status("\tOracle Server found.")
      return true
    elsif registry_enumkeys(key).include?("SYSMAN")
      print_status("\tOracle Server found.")
      return true
    elsif registry_enumkeys(key).include?("KEY_XE")
      print_status("\tOracle Server found.")
      return true
    end
    return false
  rescue
    return false
  end

  # method for Checking if database instances are installed on host - db2
  def check_db2
    key = "HKLM\\SOFTWARE\\IBM\\DB2"
    if registry_enumkeys(key).include?("GLOBAL_PROFILE")
      print_status("\tDB2 Server found.")
      return true
    end
    return false
  rescue
    return false
  end

  # method for Checking if database instances are installed on host - mysql
  def check_mysql
    key = "HKLM\\SOFTWARE"
    if registry_enumkeys(key).include?("MySQL AB")
      print_status("\tMySQL Server found.")
      return true
    end
    return false
  rescue
    return false
  end

  # method for Checking if database instances are installed on host - sybase
  def check_sybase
    key = "HKLM\\SOFTWARE\\Sybase"
    if registry_enumkeys(key).include?("SQLServer")
      print_status("\tSybase Server found.")
      return true
    elsif registry_enumkeys(key).include?("Server")
      print_status("\tSybase Server found.")
      return true
    end
    return false
  rescue
    return false
  end

  ##### deep analysis methods #####

  # method to identify mssql instances
  def enumerate_mssql
    results = []
    key = "HKLM\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\Instance Names\\SQL"
    instances = registry_enumvals(key)
    if not instances.nil? and not instances.empty?
      instances.each do |i|
        tcpkey = "HKLM\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\#{registry_getvaldata(key,i)}\\MSSQLServer\\SuperSocketNetLib\\Tcp\\IPAll"
        tcpport = registry_getvaldata(tcpkey,"TcpPort")
        print_good("\t\t+ #{registry_getvaldata(key,i)} (Port:#{tcpport})")
        results << ["mssql","instance:#{registry_getvaldata(key,i)} port:#{tcpport}","Microsoft SQL Server",tcpport]
      end
    end
    return results
  rescue
    print_error("\t\t! could not identify information")
    return results || []
  end

  # method to identify oracle instances
  def enumerate_oracle
    results = []
    found_key = false
    basekey_set = ["HKLM\\SOFTWARE\\Oracle\\SYSMAN","HKLM\\SOFTWARE\\ORACLE\\KEY_XE"]
    basekey_set.each do |basekey|
      next if found_key
      instances = registry_enumkeys(basekey)
      if instances.nil? or instances.empty?
        next
      else
        found_key = true
      end

      instances.each do |i|
        if basekey.include?"KEY_XE"
          val_ORACLE_SID = registry_getvaldata(basekey,"ORACLE_SID")
          val_ORACLE_HOME = registry_getvaldata(basekey,"ORACLE_HOME")
        else
          key = "#{basekey}\\#{i}"
          val_ORACLE_SID = registry_getvaldata(key,"ORACLE_SID")
          val_ORACLE_HOME = registry_getvaldata(key,"ORACLE_HOME")
        end
        if not exist?(val_ORACLE_HOME + "\\NETWORK\\ADMIN\\tnsnames.ora")
          print_error("\t\t! #{val_ORACLE_SID} (No Listener Found)")
          next
        end

        data_TNSNAMES = read_file(val_ORACLE_HOME + "\\NETWORK\\ADMIN\\tnsnames.ora")
        if data_TNSNAMES =~ /PORT\ \=\ (\d+)/
          port = $1
          print_good("\t\t+ #{val_ORACLE_SID} (Port:#{port})")
          results << [ "oracle","instance:#{val_ORACLE_SID} port:#{port}","Oracle Database Server",port ]
        else
          print_error("\t\t! #{val_ORACLE_SID} (No Listener Found)")
        end
      end
    end
    if not found_key
      print_error("\t\t! Oracle instances not found")
    end
    return results
  rescue
    print_error("\t\t! could not identify information")
    return results || []
  end

  # method to identify mysql instances
  def enumerate_mysql
    results = []
    basekey = "HKLM\\SOFTWARE\\MySQL AB"
    instances = registry_enumkeys(basekey)
    if  instances.nil? or instances.empty?
      return results
    end
    instances.each do |i|
      key = "#{basekey}\\#{i}"
      val_location = registry_getvaldata(key,"Location")

      data = find_mysql_conf(val_location)

      if data and data =~ /port\=(\d+)/
        port = $1
        print_good("\t\t+ MYSQL (Port:#{port})")
        results << ["mysql","instance:MYSQL port:#{port}","MySQL Server",port]
      else
        print_error("\t\t! could not identify information")
      end
    end
    return results
  rescue
    print_error("\t\t! could not identify information")
    return results || []
  end

  # method to identify sybase instances
  def enumerate_sybase
    basekey = "HKLM\\SOFTWARE\\Sybase\\SQLServer"
    instance = registry_getvaldata(basekey,"DSLISTEN")
    location = registry_getvaldata(basekey,"RootDir")
    results = []

    if not exist?(location + "\\ini\\sql.ini")
      print_error("\t\t! could not locate configuration file.")
      return results
    end

    data = read_file(location + "\\ini\\sql.ini")
    if data =~ /\[#{instance}\]([^\[]*)/
      segment = $1
    else
      print_error("\t\t! couldnt locate information.")
      return results
    end

    if segment =~ /master\=\w+\,[^\,]+\,(\d+)/
      port = $1
    else
      print_error("\t\t! couldnt locate information.")
      return results
    end

    print_good("\t\t+ #{instance} (Port:#{port})")
    results << [ "sybase","instance:#{instance} port:#{port}","Sybase SQL Server",port ]
    return results
  rescue
    print_error("\t\t! couldnt locate information.")
    return results || []
  end

  # method to identify db2 instances
  def enumerate_db2
    results = []
    cmd_i = cmd_exec("db2cmd", "-i -w /c db2ilist")
    cmd_p = cmd_exec("db2cmd", "-i -w /c db2 get dbm cfg")
    if cmd_p =~ /\ ?TCP\/IP\ Service\ name[\ ]+\(SVCENAME\)\ =\ (\w+)/
      port = $1
    else
      print_error("\t\t! could not identify instances information")
      return results
    end

    windir = session.sys.config.getenv('windir')
    getfile = session.fs.file.search(windir + "\\system32\\drivers\\etc\\","services.*",recurse=true,timeout=-1)

    data = nil
    getfile.each do |file|
      if exist?("#{file['path']}\\#{file['name']}")
        data = read_file("#{file['path']}\\#{file['name']}")
        break if not data.nil?
      end
    end

    if data and data =~ /#{port}[\ \t]+(\d+)/
      port_t = $1
    else
      print_error("\t\t! could not identify instances information")
      return results
    end

    cmd_i.split("\n").compact.each do |line|
      stripped=line.strip
      print_good("\t\t+ #{stripped} (Port:#{port_t})")
      results << [ "db2","instance:#{stripped} port:#{port_t}","DB2 Server",port_t ]
    end

    return results

  rescue
    print_error("\t\t! could not identify instances information")
    return results || []
  end

  ##### helper methods #####

  def find_mysql_conf(val_location)
    data = nil
    if exist?(val_location + "\\my.ini")
      data = read_file(val_location + "\\my.ini")
    elsif exist?(val_location + "\\my.cnf")
      data = read_file(val_location + "\\my.cnf")
    else
      sysdriv=session.sys.config.getenv('SYSTEMDRIVE')
      getfile = session.fs.file.search(sysdriv + "\\","my.ini",recurse=true,timeout=-1)
      getfile.each do |file|
        if exist?("#{file['path']}\\#{file['name']}")
          data = read_file("#{file['path']}\\#{file['name']}")
          break
        end
      end
    end
    return data
  end
end

