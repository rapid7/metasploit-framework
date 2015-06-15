##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  include Msf::Exploit::Remote::Ftp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'FTP Version Scanner',
      'Description' => 'Detect FTP Version.',
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE
    )
  end

  def run_host(_target_host)
    begin
      if connect(true, false)
        banner_sanitized = Rex::Text.to_hex_ascii(banner)
        print_status("#{rhost}:#{rport} FTP Banner: '#{banner_sanitized}'")
        report_service(host: rhost, port: rport, name: 'ftp', info: banner_sanitized)
      end
    rescue ::Interrupt
      raise $ERROR_INFO
    rescue ::Rex::ConnectionError, ::IOError
    ensure
      disconnect
    end
  end
end
