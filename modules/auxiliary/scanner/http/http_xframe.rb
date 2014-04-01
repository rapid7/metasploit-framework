##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(update_info(info,
      'Name'        => 'X-Frame-Options Header Detection',
      'Description' => %q{
        Display HTTP X-Frame-Options Header Detection information about each system. 
        This header is used to avoid clickjacking attacks.
      },
      'Author'      => ['rick2600'],
      'References'  => 
        [
          ['URL','https://developer.mozilla.org/en-US/docs/HTTP/X-Frame-Options'],
          ['URL','https://www.owasp.org/index.php/Clickjacking_Defense_Cheat_Sheet']
        ],
      'License'     => MSF_LICENSE
    ))

    register_options([
        OptBool.new('SSL', [ false, "Negotiate SSL for outgoing connections", false]),
      ])
  end

  def run_host(ip)
    res = send_request_raw({'method' => 'HEAD'})

    if res
      xframe = res.headers['X-Frame-Options']

      if xframe
        print_status("#{peer} - X-Frame-Options: #{xframe}")
        report_note({
          :data => xframe,
          :type => "xframe.data",
          :host => ip,
          :port => rport
        })
      else
        print_good("#{peer} No X-Frame-Options found.")
        vprint_good("Headers:\n#{res.headers}")
      end
    else
      print_error("#{peer} No headers were returned.")
    end
  end

end
