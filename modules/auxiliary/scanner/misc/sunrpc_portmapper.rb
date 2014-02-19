##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::SunRPC
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'          => 'SunRPC Portmap Program Enumerator',
      'Description'   => %q{
          This module calls the target portmap service and enumerates all
        program entries and their running port numbers.
      },
      'Author'	       => ['<tebo [at] attackresearch.com>'],
      'References'	 =>
        [
          ['URL',	'http://www.ietf.org/rfc/rfc1057.txt'],
        ],
      'License'	=> MSF_LICENSE
    )

    register_options([], self.class)
  end

  def run_host(ip)
    vprint_status "#{ip}:#{rport} - SunRPC - Enumerating programs"

    begin
      program		= 100000
      progver		= 2
      procedure	= 4

      sunrpc_create('udp', program, progver)
      sunrpc_authnull()
      resp = sunrpc_call(procedure, "")

      progs = resp[3,1].unpack('C')[0]
      maps = []
      if (progs == 0x01)
        print_good("#{ip}:#{rport} - Programs available")
        while XDR.decode_int!(resp) == 1 do
          map = XDR.decode!(resp, Integer, Integer, Integer, Integer)
          maps << map
        end
      end
      sunrpc_destroy

      lines = []
      maps.each do |map|
        prog, vers, prot, port = map[0,4]
        prot = 	if prot == 0x06; "tcp"
          elsif prot == 0x11; "udp"
          end
        lines << "\t#{progresolv(prog)} - #{port}/#{prot}"

        report_service(
          :host => ip,
          :port => port,
          :proto => prot,
          :name => progresolv(prog),
          :info => "Prog: #{prog} Version: #{vers} - via portmapper"
        )
      end

      # So we don't print a line for every program version
      lines.uniq.each {|line| print_line(line)}

    rescue ::Rex::Proto::SunRPC::RPCTimeout
    end
  end

end
