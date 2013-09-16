##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'		=> 'X11 No-Auth Scanner',
      'Description'	=> %q{
        This module scans for X11 servers that allow anyone
        to connect without authentication.
      },
      'Author'	=> ['tebo <tebodell[at]gmail.com>'],
      'References'	=>
        [
          ['OSVDB', '309'],
          ['CVE', '1999-0526'],
        ],
      'License'	=> MSF_LICENSE
    )

    register_options([
      Opt::RPORT(6000)
    ],self.class)
  end

  def run_host(ip)

    begin

      connect

      # X11.00 Null Auth Connect
      sock.put("\x6c\x00\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00")
      response = sock.get_once

      disconnect

      if(response)
        success = response[0,1].unpack('C')[0]
      end


      if(success == 1)
        vendor_len = response[24,2].unpack('v')[0]
        vendor = response[40,vendor_len].unpack('A*')[0]
        print_status("#{ip} Open X Server (#{vendor})")
        #Add Report
        report_note(
          :host	=> ip,
          :proto => 'tcp',
          :sname	=> 'x11',
          :port	=> rport,
          :type	=> 'Open X Server',
          :data	=> "Open X Server (#{vendor})"
      )
      elsif (success == 0)
        print_status("#{ip} Access Denied")
      else
        # X can return a reason for auth failure but we don't really care for this
      end

    rescue ::Rex::ConnectionError
    rescue ::Errno::EPIPE
    end

  end

end
