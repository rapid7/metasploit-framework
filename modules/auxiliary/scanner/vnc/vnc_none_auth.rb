##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/rfb'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'VNC Authentication None Detection',
      'Description' => 'Detect VNC servers that support the "None" authentication method.',
      'References'  =>
        [
          ['CVE', '2006-2369'], # a related instance where "None" could be offered and used when not configured as allowed.
          ['URL', 'http://en.wikipedia.org/wiki/RFB'],
          ['URL', 'http://en.wikipedia.org/wiki/Vnc'],
        ],
      'Author'      =>
        [
          'Matteo Cantoni <goony[at]nothink.org>',
          'jduck'
        ],
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(5900)
      ])
  end

  def run_host(target_host)
    begin
      connect
      vnc = Rex::Proto::RFB::Client.new(sock)
      unless vnc.handshake
        print_error("#{target_host}:#{rport} - Handshake failed: #{vnc.error}")
        return
      end

      ver = "#{vnc.majver}.#{vnc.minver}"
      print_good("#{target_host}:#{rport} - VNC server protocol version: #{ver}")
      svc = report_service(
        :host => rhost,
        :port => rport,
        :proto => 'tcp',
        :name => 'vnc',
        :info => "VNC protocol version #{ver}"
      )

      type = vnc.negotiate_authentication
      unless type
        print_error("#{target_host}:#{rport} - Auth negotiation failed: #{vnc.error}")
        return
      end

      # Show the allowed security types
      sec_type = []
      vnc.auth_types.each { |type|
        sec_type << Rex::Proto::RFB::AuthType.to_s(type)
      }
      print_status("#{target_host}:#{rport} - VNC server security types supported: #{sec_type.join(",")}")

      if (vnc.auth_types.include? Rex::Proto::RFB::AuthType::None)
        print_good("#{target_host}:#{rport} - VNC server security types includes None, free access!")
        report_vuln(
          {
            :host         => rhost,
            :service      => svc,
            :name         => self.name,
            :info         => "Module #{self.fullname} identified the VNC 'none' security type: #{sec_type.join(", ")}",
            :refs         => self.references,
            :exploited_at => Time.now.utc
          })
      end
    ensure
      disconnect
    end

  end
end
