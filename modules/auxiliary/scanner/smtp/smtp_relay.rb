##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Smtp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info={})
    super(
        update_info(
            info,
            'Name'        => 'SMTP Open Relay Detection',
            'Description' => %q{
              This module tests if an SMTP server will accept (via a code 250)
              an e-mail from the provided FROM: address. If successful, a random
              e-mail message may be sent to the named RCPT: address.
            },
            'References'  =>
                [
                    ['URL', 'http://www.ietf.org/rfc/rfc2821.txt'],
                ],
            'Author'      => 'Campbell Murray',
            'License'     => MSF_LICENSE
        )
    )
  end

  def peer
    "#{rhost}:#{rport}"
  end

  def run_host(ip)
    begin
      connect
    rescue
      print_error("#{peer} - Unable to establish an SMTP session")
      return
    end

    banner_sanitized = Rex::Text.to_hex_ascii(banner.to_s)
    print_status("#{peer} - SMTP #{banner_sanitized}")
    report_service(:host => rhost, :port => rport, :name => "smtp", :info => banner)
    do_test_relay
  end

  def do_test_relay
    res = raw_send_recv("EHLO X\r\n")
    vprint_status("#{peer} - #{res.inspect}")

    res = raw_send_recv("MAIL FROM: #{datastore['MAILFROM']}\r\n")
    vprint_status("#{peer} - #{res.inspect}")

    res = raw_send_recv("RCPT TO: #{datastore['MAILTO']}\r\n")
    vprint_status("#{peer} - #{res.inspect}")

    res = raw_send_recv("DATA\r\n")
    vprint_status("#{peer} - #{res.inspect}")

    res = raw_send_recv("#{Rex::Text.rand_text_alpha(rand(10)+5)}\r\n.\r\n")
    vprint_status("#{peer} - #{res.inspect}")

    if res =~ /250/
      print_good("#{peer} - Potential open SMTP relay detected")
    else
      print_status "#{peer} - No relay detected"
    end
  end
end
