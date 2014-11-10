##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::UDPScanner

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'           => 'Gather Steam Server Information',
        'Description'    => %q(
          This module uses the A2S_INFO request to obtain information from a Steam server.
        ),
        'Author'         => 'Jon Hart <jon_hart[at]rapid7.com',
        'References'     =>
          [
            # TODO: add more from https://developer.valvesoftware.com/wiki/Server_queries,
            # perhaps in different modules
            ['URL', 'https://developer.valvesoftware.com/wiki/Server_queries#A2S_INFO']
          ],
        'License'        => MSF_LICENSE
      )
    )

    register_options(
    [
      Opt::RPORT(27015)
    ], self.class)

  end

  # TODO: construct the appropriate probe here.
  def build_probe
    @probe ||= "\xFF\xFF\xFF\xFFTSource Engine Query\x00"
  end

  # Called for each response packet
  def scanner_process(response, src_host, _src_port)
    return unless response.size >= 19
    @results[src_host] ||= []
    puts "Got something from #{src_host}"
    #puts response.unpack("NCCZ*Z*Z*Z*SCCCCCCCZ*C")

  end

  # Called after the scan block
  def scanner_postscan(_batch)
    @results.each_pair do |host, info|
      report_host(host: host)
      report_service(
        host: host,
        proto: 'udp',
        port: rport,
        name: 'Steam',
        info: info
      )
    end
  end
end
