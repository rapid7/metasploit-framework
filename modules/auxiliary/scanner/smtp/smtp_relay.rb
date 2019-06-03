##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Smtp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'SMTP Open Relay Detection',
      'Description' => %q{
        This module tests if an SMTP server will accept (via a code 250)
        an e-mail by using a variation of testing methods.
        Some of the extended methods will try to abuse configuration or mailserver flaws.
      },
      'References'  =>
        [
          ['URL', 'http://www.ietf.org/rfc/rfc2821.txt'],
          ['URL', 'https://svn.nmap.org/nmap/scripts/smtp-open-relay.nse'],
        ],
      'Author'      =>
        [
          'Campbell Murray',
          'xistence <xistence[at]0x90.nl>',
        ],
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        OptBool.new('EXTENDED', [true, 'Do all the 16 extended checks', false]),
      ])
  end

  def run_host(ip)
    begin
      connect
      banner_sanitized = Rex::Text.to_hex_ascii(banner.to_s)
      print_good("SMTP #{banner_sanitized}")
      report_service(:host => rhost, :port => rport, :name => "smtp", :info => banner)

      if datastore['EXTENDED']

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
      else
        do_test_relay(nil, "MAIL FROM:<#{datastore['MAILFROM']}>", "RCPT TO:<#{datastore['MAILTO']}>")
    end
    rescue
      print_error("Unable to establish an SMTP session")
      return
    end
  end

  def do_test_relay(testnumber, mailfrom, mailto)
    begin
      connect

      res = raw_send_recv("EHLO X\r\n")
      vprint_status("#{res.inspect}")

      res = raw_send_recv("#{mailfrom}\r\n")
      vprint_status("#{res.inspect}")

      res = raw_send_recv("#{mailto}\r\n")
      vprint_status("#{res.inspect}")

      res = raw_send_recv("DATA\r\n")
      vprint_status("#{res.inspect}")

      res = raw_send_recv("#{Rex::Text.rand_text_alpha(rand(10)+5)}\r\n.\r\n")
      vprint_status("#{res.inspect}")

      if res =~ /250/
        if testnumber.nil?
          print_good("Potential open SMTP relay detected: - #{mailfrom} -> #{mailto}")
        else
          print_good("Test ##{testnumber} - Potential open SMTP relay detected: - #{mailfrom} -> #{mailto}")
        end
      else
        if testnumber.nil?
          print_status "No relay detected"
        else
          print_status "Test ##{testnumber} - No relay detected"
        end
      end

    rescue
      print_error("Test ##{testnumber} - Unable to establish an SMTP session")
      return
    end
  end
end
