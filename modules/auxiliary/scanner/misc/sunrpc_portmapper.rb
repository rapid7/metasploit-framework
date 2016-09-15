##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SunRPC
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'SunRPC Portmap Program Enumerator',
      'Description' => '
        This module calls the target portmap service and enumerates all program
        entries and their running port numbers.
      ',
      'Author'      => ['<tebo[at]attackresearch.com>'],
      'References'  =>
        [
          ['URL',	'http://www.ietf.org/rfc/rfc1057.txt']
        ],
      'License'	=> MSF_LICENSE
    )
  end

  def run_host(ip)
    peer = "#{ip}:#{rport}"
    vprint_status "SunRPC - Enumerating programs"

    begin
      program		= 100000
      progver		= 2
      procedure	= 4

      sunrpc_create('udp', program, progver)
      sunrpc_authnull
      resp = sunrpc_call(procedure, "")

      progs = resp[3, 1].unpack('C')[0]
      maps = []
      if (progs == 0x01)
        while XDR.decode_int!(resp) == 1
          maps << XDR.decode!(resp, Integer, Integer, Integer, Integer)
        end
      end
      sunrpc_destroy
      return if maps.empty?
      vprint_good("Found #{maps.size} programs available")

      table = Rex::Text::Table.new(
        'Header'  => "SunRPC Programs for #{ip}",
        'Indent'  => 1,
        'Columns' => %w(Name Number Version Port Protocol)
      )

      maps.each do |map|
        prog, vers, prot_num, port = map[0, 4]
        thing = "RPC Program ##{prog} v#{vers} on port #{port} w/ protocol #{prot_num}"
        if prot_num == 0x06
          proto = 'tcp'
        elsif prot_num == 0x11
          proto = 'udp'
        else
          print_error("#{peer}: unknown protocol number for #{thing}")
          next
        end

        resolved = progresolv(prog)
        table << [ resolved, prog, vers, port, proto ]
        report_service(
          host: ip,
          port: port,
          proto: proto,
          name: resolved,
          info: "Prog: #{prog} Version: #{vers} - via portmapper"
        )
      end

      print_good(table.to_s)
    rescue ::Rex::Proto::SunRPC::RPCTimeout, ::Rex::Proto::SunRPC::RPCError => e
      vprint_error(e.to_s)
    end
  end
end
