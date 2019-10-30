##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::LDAP
  include Msf::Post::Windows::Accounts

  UAC_DISABLED = 0x02
  USER_FIELDS = ['sAMAccountName',
                 'name',
                 'userPrincipalName',
                 'userAccountControl',
                 'lockoutTime',
                 'mail',
                 'primarygroupid',
                 'description'].freeze

  def initialize(info = {})
    super(update_info(
      info,
      'Name'         => 'Windows Gather Active Directory Users',
      'Description'  => %{
        This module will enumerate user accounts in the default Active Domain (AD) directory and stores
      them in the database. If GROUP_MEMBER is set to the DN of a group, this will list the members of
      that group by performing a recursive/nested search (i.e. it will list users who are members of
      groups that are members of groups that are members of groups (etc) which eventually include the
      target group DN.
      },
      'License'      => MSF_LICENSE,
      'Author'       => [
        'Ben Campbell',
        'Carlos Perez <carlos_perez[at]darkoperator.com>',
        'Stuart Morgan <stuart.morgan[at]mwrinfosecurity.com>'
      ],
      'Platform'     => [ 'win' ],
      'SessionTypes' => [ 'meterpreter' ]
    ))

    register_options([
      OptBool.new('STORE_LOOT', [true, 'Store file in loot.', false]),
      OptBool.new('EXCLUDE_LOCKED', [true, 'Exclude in search locked accounts..', false]),
      OptBool.new('EXCLUDE_DISABLED', [true, 'Exclude from search disabled accounts.', false]),
      OptString.new('ADDITIONAL_FIELDS', [false, 'Additional fields to retrieve, comma separated', nil]),
      OptString.new('FILTER', [false, 'Customised LDAP filter', nil]),
      OptString.new('GROUP_MEMBER', [false, 'Recursively list users that are effectve members of the group DN specified.', nil]),
      OptEnum.new('UAC', [true, 'Filter on User Account Control Setting.', 'ANY',
                          [
                            'ANY',
                            'NO_PASSWORD',
                            'CHANGE_PASSWORD',
                            'NEVER_EXPIRES',
                            'SMARTCARD_REQUIRED',
                            'NEVER_LOGGEDON'
                          ]])
    ])
  end

  def run
    @user_fields = USER_FIELDS.dup

    if datastore['ADDITIONAL_FIELDS']
      additional_fields = datastore['ADDITIONAL_FIELDS'].gsub(/\s+/, "").split(',')
      @user_fields.push(*additional_fields)
    end

    max_search = datastore['MAX_SEARCH']

    begin
      q = query(query_filter, max_search, @user_fields)
    rescue ::RuntimeError, ::Rex::Post::Meterpreter::RequestError => e
      # Can't bind or in a network w/ limited accounts
      print_error(e.message)
      return
    end

    if q.nil? || q[:results].empty?
      print_status('No results returned.')
    else
      results_table = parse_results(q[:results])
      print_line results_table.to_s

      if datastore['STORE_LOOT']
        stored_path = store_loot('ad.users', 'text/plain', session, results_table.to_csv)
        print_good("Results saved to: #{stored_path}")
      end
    end
  end

  def account_disabled?(uac)
    (uac & UAC_DISABLED) > 0
  end

  def account_locked?(lockout_time)
    lockout_time > 0
  end

  # Takes the results of LDAP query, parses them into a table
  # and records and usernames as {Metasploit::Credential::Core}s in
  # the database.
  #
  # @param [Array<Array<Hash>>] the LDAP query results to parse
  # @return [Rex::Text::Table] the table containing all the result data
  def parse_results(results)
    domain = datastore['DOMAIN'] || get_domain
    domain_ip = client.net.resolve.resolve_host(domain)[:ip]
    # Results table holds raw string data
    results_table = Rex::Text::Table.new(
      'Header'     => "Domain Users",
      'Indent'     => 1,
      'SortIndex'  => -1,
      'Columns'    => @user_fields
    )

    results.each do |result|
      row = []

      result.each do |field|
        if field.nil?
          row << ""
        else
          row << field[:value]
        end
      end

      username = result[@user_fields.index('sAMAccountName')][:value]
      uac = result[@user_fields.index('userAccountControl')][:value]
      lockout_time = result[@user_fields.index('lockoutTime')][:value]
      store_username(username, uac, lockout_time, domain, domain_ip)

      results_table << row
    end
    results_table
  end

  # Builds the LDAP query 'filter' used to find our User Accounts based on
  # criteria set by user in the Datastore.
  #
  # @return [String] the LDAP query string
  def query_filter
    inner_filter = '(objectCategory=person)(objectClass=user)'
    inner_filter << '(!(lockoutTime>=1))' if datastore['EXCLUDE_LOCKED']
    inner_filter << '(!(userAccountControl:1.2.840.113556.1.4.803:=2))' if datastore['EXCLUDE_DISABLED']
    inner_filter << "(memberof:1.2.840.113556.1.4.1941:=#{datastore['GROUP_MEMBER']})" if datastore['GROUP_MEMBER']
    inner_filter << "(#{datastore['FILTER']})" if datastore['FILTER'] != ""
    case datastore['UAC']
      when 'ANY'
      when 'NO_PASSWORD'
        inner_filter << '(userAccountControl:1.2.840.113556.1.4.803:=32)'
      when 'CHANGE_PASSWORD'
        inner_filter << '(!sAMAccountType=805306370)(pwdlastset=0)'
      when 'NEVER_EXPIRES'
        inner_filter << '(userAccountControl:1.2.840.113556.1.4.803:=65536)'
      when 'SMARTCARD_REQUIRED'
        inner_filter << '(userAccountControl:1.2.840.113556.1.4.803:=262144)'
      when 'NEVER_LOGGEDON'
        inner_filter << '(|(lastlogon=0)(!lastlogon=*))'
    end
    "(&#{inner_filter})"
  end

  def store_username(username, uac, lockout_time, realm, domain_ip)
    service_data = {
      address: domain_ip,
      port: 445,
      service_name: 'smb',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :session,
      session_id: session_db_id,
      post_reference_name: refname,
      username: username,
      realm_value: realm,
      realm_key: Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN
    }

    credential_data.merge!(service_data)

    # Create the Metasploit::Credential::Core object
    credential_core = create_credential(credential_data)

    if account_disabled?(uac.to_i)
      status = Metasploit::Model::Login::Status::DISABLED
    elsif account_locked?(lockout_time.to_i)
      status = Metasploit::Model::Login::Status::LOCKED_OUT
    else
      status = Metasploit::Model::Login::Status::UNTRIED
    end

    # Assemble the options hash for creating the Metasploit::Credential::Login object
    login_data = {
      core: credential_core,
      status: status
    }

    login_data[:last_attempted_at] = DateTime.now unless (status == Metasploit::Model::Login::Status::UNTRIED)

    # Merge in the service data and create our Login
    login_data.merge!(service_data)
    create_credential_login(login_data)
  end
end
