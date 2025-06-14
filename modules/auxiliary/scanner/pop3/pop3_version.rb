##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'POP3 Banner Grabber',
      'Description' => 'POP3 Banner Grabber',
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE
    )
    register_options([
      Opt::RPORT(110)
    ])
  end

  def run_host(ip)
    begin
      connect
      banner = sock.get_once(-1, 30)
      banner_sanitized = Rex::Text.to_hex_ascii(banner.to_s)
      print_good("#{ip}:#{rport} POP3 #{banner_sanitized}")
      report_service(:host => rhost, :port => rport, :name => "pop3", :info => banner)
    rescue ::Rex::ConnectionError
    rescue ::EOFError
      print_error("#{ip}:#{rport} - The service failed to respond")
    rescue ::Exception => e
      print_error("#{ip}:#{rport} - #{e} #{e.backtrace}")
    end
  end
end
