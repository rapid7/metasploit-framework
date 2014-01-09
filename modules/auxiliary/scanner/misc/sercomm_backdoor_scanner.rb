##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(update_info(info,
      'Name'        => 'SerComm Network Device Backdoor Detection',
      'Description' => %q{
        This module can identify SerComm manufactured network devices which
        contain a backdoor, allowing command injection or account disclosure.
      },
      'Author'      => 'Matt "hostess" Andreko <mandreko[at]accuvant.com>',
      'License'     => MSF_LICENSE
    ))

    register_options([
        Opt::RPORT(32764)
      ])
  end

  def run_host(ip)

    begin
      connect

      sock.put(Rex::Text.rand_text(5))
      res = sock.get_once

      disconnect

      if (res && res.start_with?("MMcS"))
        print_good("#{ip}:#{rport} - Possible backdoor detected - Big Endian")
      elsif (res && res.start_with?("ScMM"))
        print_good("#{ip}:#{rport} - Possible backdoor detected - Little Endian")
      else
        print_error("#{ip}:#{rport} - Backdoor not detected.")
      end

    rescue Rex::ConnectionError => e
      print_error("Connection failed: #{e.class}: #{e}")
    end

  end
end
