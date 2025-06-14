##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Imap
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'IMAP4 Banner Grabber',
      'Description' => 'IMAP4 Banner Grabber',
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE
    )
  end

  def run_host(ip)
    begin
      connect
      banner_sanitized = Rex::Text.to_hex_ascii(banner.to_s)
      print_good("#{ip}:#{rport} IMAP #{banner_sanitized}")
      report_service(:host => rhost, :port => rport, :name => "imap", :info => banner)
    rescue ::Rex::ConnectionError
    rescue ::EOFError
      print_error("#{ip}:#{rport} - The service failed to respond")
    rescue ::Exception => e
      print_error("#{ip}:#{rport} - #{e} #{e.backtrace}")
    end
  end
end
