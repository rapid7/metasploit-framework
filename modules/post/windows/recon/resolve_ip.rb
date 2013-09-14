# -*- coding: binary -*-

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Windows Recon Resolve IP',
        'Description'   => %q{ This module reverse resolves a range or IP to a hostname},
        'License'       => MSF_LICENSE,
        'Author'        => [ 'mubix' ],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ]
      ))
    register_options(
      [
        OptAddress.new("ADDRESS" , [ false, "Enumerate currently configured shares"]),
        OptAddressRange.new("RANGE"  , [ false, "Enumerate Recently mapped shares"])
      ], self.class)

  end

  def resolve_ip(ip)
    ip_ino = Rex::Socket.addr_aton(ip)
    begin
      ptr2dns = session.railgun.ws2_32.gethostbyaddr(ip_ino,4,2)
      memtext = client.railgun.memread(ptr2dns['return'],255)
      host_inmem = memtext.split(ip_ino)[1].split("\00")[0]
      print_good("#{ip} resolves to #{host_inmem}")
    rescue Rex::Post::Meterpreter::RequestError
      print_error("Failed to resolve #{ip}")
    end
  end

  def run
    if datastore['ADDRESS']
      resolve_ip(datastore['ADDRESS'])
    end

    if datastore['RANGE']
      rexrange = Rex::Socket::RangeWalker.new(datastore['RANGE'])
      rexrange.each do |ip|
        resolve_ip(ip)
      end
    end
  end

end

