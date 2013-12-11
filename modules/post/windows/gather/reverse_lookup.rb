##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

  def initialize(info={})
    super( update_info( info,
      'Name'                 => "Windows Gather IP Range Reverse Lookup",
      'Description'          => %q{
        This module uses Railgun, calling the gethostbyaddr function to resolve a hostname
        to an IP.
      },
      'License'              => MSF_LICENSE,
      'Platform'             => ['win'],
      'SessionTypes'         => ['meterpreter'],
      'Author'               => [ 'mubix' ]
      ))
    register_options(
      [
        OptAddressRange.new('RHOSTS', [true, 'IP Range to perform reverse lookup against.'])

      ], self.class)
  end


  def run

    #Add ws2_32 just in case it isn't there...
    session.railgun.ws2_32

    #Check if gethostbyaddr is available to us
    modhandle = session.railgun.kernel32.GetModuleHandleA('ws2_32.dll')
    if modhandle['return'] == 0
      print_error("WS2_32 isn't available at this time, exiting")
      return
    else
      procaddr = session.railgun.kernel32.GetProcAddress(modhandle['return'],'gethostbyaddr')
      if procaddr['return'] == 0
        print_error("WS2_32 was loaded but does not have the gethostbyaddr function, exiting")
        return
      end
    end

    #Generates IP list based on RHOSTS - RangeWalker rocks....
    iplist = Rex::Socket::RangeWalker.new(datastore['RHOSTS'])

    iplist.each do |x|
      #Converts an IP in string formate to network byte order format
      nbi = Rex::Socket.addr_aton(x)

      #Call gethostbyaddr
      result = session.railgun.ws2_32.gethostbyaddr(nbi.to_s,nbi.size,2)
      if result['return'] == 0
        vprint_status("#{x} did not resolve")
      else
        struct = session.railgun.memread(result['return'],100)
        hostname = struct.split(nbi)[1].split("\0")[0]
        print_good("#{x} resolves to #{hostname}")
      end
    end
  end
end
