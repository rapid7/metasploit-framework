##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Imap
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info={})
    super(
        update_info(
            info,
            'Name'        => 'IMAP4 Banner Grabber',
            'Description' => 'IMAP4 Banner Grabber',
            'Author'      => 'hdm',
            'License'     => MSF_LICENSE
        )
    )
  end

  def run_host(ip)
    begin
      res = connect
      banner_sanitized = Rex::Text.to_hex_ascii(banner.to_s)
      print_status("#{ip}:#{rport} IMAP #{banner_sanitized}")
      report_service(:host => rhost, :port => rport, :name => "imap", :info => banner)
    rescue ::Rex::ConnectionError
    rescue ::Exception => e
      print_error("#{rhost}:#{rport} #{e} #{e.backtrace}")
    end
  end

end
