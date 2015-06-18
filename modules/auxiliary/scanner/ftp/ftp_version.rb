##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  include Msf::Exploit::Remote::Ftp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Recog

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
        recog_banner = banner.gsub(/^220[ -](.*)\r\n/) { "#{Regexp.last_match(1)}\r\n" }.strip
        info = { "banner" => recog_banner }.merge(recog_info(peer, 'ftp.banner', recog_banner) || {})
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
