##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Smtp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'SMTP Extended Open Relay Detection',
      'Description' => %q{
        This module tests if an SMTP server will accept (via a code 250)
        an e-mail by using a variation of testing methods.
        Some of these methods will try to abuse configuration or mailserver flaws.
      },
      'References'  =>
        [
          ['URL', 'https://svn.nmap.org/nmap/scripts/smtp-open-relay.nse'],
        ],
      'Author'      => 'xistence <xistence[at]0x90.nl>',
      'License'     => MSF_LICENSE
    )
  end

  def peer
    "#{rhost}:#{rport}"
  end

  def run_host(ip)
    begin
      connect
      banner_sanitized = Rex::Text.to_hex_ascii(banner.to_s)
      print_status("#{peer} - SMTP #{banner_sanitized}")
      report_service(:host => rhost, :port => rport, :name => "smtp", :info => banner)

      if banner_sanitized =~ /220 (.*) /
        serverhost = $1
      end

      mailfromuser = datastore['MAILFROM'].split("@").first
      mailfromdomain = datastore['MAILFROM'].split("@").last
      mailtouser = datastore['MAILTO'].split("@").first
      mailtodomain = datastore['MAILTO'].split("@").last

      do_test_relay(1, "MAIL FROM:<>", "RCPT TO:<#{datastore['MAILTO']}>")
      do_test_relay(2, "MAIL FROM:<#{datastore['MAILFROM']}>", "RCPT TO:<#{datastore['MAILTO']}>")
      do_test_relay(3, "MAIL FROM:<#{mailfromuser}@#{serverhost}>", "RCPT TO:<#{datastore['MAILTO']}>")
      do_test_relay(4, "MAIL FROM:<#{mailfromuser}@[#{rhost}]>", "RCPT TO:<#{mailtouser}@[#{rhost}]>")
      do_test_relay(5, "MAIL FROM:<#{mailfromuser}@[#{rhost}]>", "RCPT TO:<#{mailtouser}\%#{mailtodomain}@[#{rhost}]>")
      do_test_relay(6, "MAIL FROM:<#{mailfromuser}@[#{rhost}]>", "RCPT TO:<#{mailtouser}\%#{mailtodomain}@#{serverhost}>")
      do_test_relay(7, "MAIL FROM:<#{mailfromuser}@[#{rhost}]>", "RCPT TO:<\"#{mailtouser}@#{mailtodomain}\">")
      do_test_relay(8, "MAIL FROM:<#{mailfromuser}@[#{rhost}]>", "RCPT TO:<\"#{mailtouser}\%#{mailtodomain}\">")
      do_test_relay(9, "MAIL FROM:<#{mailfromuser}@[#{rhost}]>", "RCPT TO:<#{mailtouser}@#{mailtodomain}@[#{rhost}]>")
      do_test_relay(10, "MAIL FROM:<#{mailfromuser}@[#{rhost}]>", "RCPT TO:<\"#{mailtouser}@#{mailtodomain}\"@[#{rhost}]>")
      do_test_relay(11, "MAIL FROM:<#{mailfromuser}@[#{rhost}]>", "RCPT TO:<#{mailtouser}@#{mailtodomain}@#{serverhost}>")
      do_test_relay(12, "MAIL FROM:<#{mailfromuser}@[#{rhost}]>", "RCPT TO:<@[#{rhost}]:#{mailtouser}@#{mailtodomain}>")
      do_test_relay(13, "MAIL FROM:<#{mailfromuser}@[#{rhost}]>", "RCPT TO:<@#{serverhost}:#{mailtouser}@#{mailtodomain}>")
      do_test_relay(14, "MAIL FROM:<#{mailfromuser}@[#{rhost}]>", "RCPT TO:<#{mailtodomain}!#{mailtouser}>")
      do_test_relay(15, "MAIL FROM:<#{mailfromuser}@[#{rhost}]>", "RCPT TO:<#{mailtodomain}!#{mailtouser}@[#{rhost}]>")
      do_test_relay(16, "MAIL FROM:<#{mailfromuser}@[#{rhost}]>", "RCPT TO:<#{mailtodomain}!#{mailtouser}@#{serverhost}>")

    rescue
      print_error("#{peer} - Unable to establish an SMTP session")
      return
    end
  end

  def do_test_relay(testnumber, mailfrom, mailto)
    begin
      connect

      res = raw_send_recv("EHLO X\r\n")
      vprint_status("#{peer} - #{res.inspect}")

      res = raw_send_recv("#{mailfrom}\r\n")
      vprint_status("#{peer} - #{res.inspect}")

      res = raw_send_recv("#{mailto}\r\n")
      vprint_status("#{peer} - #{res.inspect}")

      res = raw_send_recv("DATA\r\n")
      vprint_status("#{peer} - #{res.inspect}")

      res = raw_send_recv("#{Rex::Text.rand_text_alpha(rand(10)+5)}\r\n.\r\n")
      vprint_status("#{peer} - #{res.inspect}")

      if res =~ /250/
        print_good("#{peer} - Test ##{testnumber} - Potential open SMTP relay detected: - #{mailfrom} -> #{mailto}")
      else
        print_status "#{peer} - Test ##{testnumber} - No relay detected"
      end

    rescue
      print_error("#{peer} - Test ##{testnumber} Unable to establish an SMTP session")
      return
    end
  end
end
