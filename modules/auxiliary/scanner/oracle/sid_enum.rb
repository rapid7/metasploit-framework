##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::TNS
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Oracle TNS Listener SID Enumeration',
      'Description'    => %q{
        This module simply queries the TNS listner for the Oracle SID.
        With Oracle 9.2.0.8 and above the listener will be protected and
        the SID will have to be bruteforced or guessed.
      },
      'Author'         => [ 'CG', 'MC' ],
      'License'        => MSF_LICENSE,
      'DisclosureDate' => 'Jan 7 2009'
    ))

    register_options(
      [
        Opt::RPORT(1521)
      ], self.class)

    deregister_options('RHOST')
  end

  def run_host(ip)
    begin
      connect

      pkt = tns_packet("(CONNECT_DATA=(COMMAND=STATUS))")

      sock.put(pkt)

      select(nil,nil,nil,0.5)

      data = sock.get_once

        if ( data and data =~ /ERROR_STACK/ )
          print_error("TNS listener protected for #{ip}...")
        else
          if(not data)
            print_error("#{ip} Connection but no data")
          else
            sid = data.scan(/INSTANCE_NAME=([^\)]+)/)
              sid.uniq.each do |s|
                report_note(
                  :host   => ip,
                  :port	=> rport,
                  :type   => "oracle_sid",
                  :data   => "PORT=#{rport}, SID=#{s}",
                  :update	=> :unique_data
                )
                print_good("Identified SID for #{ip}:#{rport} #{s}")
              end
            service_name = data.scan(/SERVICE_NAME=([^\)]+)/)
              service_name.uniq.each do |s|
                report_note(
                  :host   => ip,
                  :port	=> rport,
                  :type   => "oracle_service_name",
                  :data   => "PORT=#{rport}, SERVICE_NAME=#{s}",
                  :update	=> :unique_data
                )
                print_status("Identified SERVICE_NAME for #{ip}:#{rport} #{s}")
              end
          end
        end
      disconnect
    rescue ::Rex::ConnectionError
    rescue ::Errno::EPIPE
    end
  end
end
