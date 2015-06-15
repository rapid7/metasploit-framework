##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'recog'

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

  def peer
    "#{rhost}:#{rport}"
  end

  def run_host(_target_host)
    begin
      if connect(true, false) && banner && banner =~ /^220[ -]/
        recog_banner = banner.gsub(/^220[ -](.*)\r\n/) { "#{Regexp.last_match(1)}\r\n" }
        sanitized_banner = Rex::Text.to_hex_ascii(recog_banner)
        unless info = Recog::Nizer.match('ftp.banner', recog_banner)
          info = sanitized_banner
          print_warning("#{peer} -- no Recog match: #{sanitized_banner}")
        end
        print_status("#{peer} FTP Banner: '#{sanitized_banner}'")
        report_service(host: rhost, port: rport, name: 'ftp', info: info.to_s)
      end
    rescue ::Interrupt
      raise $ERROR_INFO
    rescue ::Rex::ConnectionError, ::IOError
    ensure
      disconnect
    end
  end
end
